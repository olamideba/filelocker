using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FileLocker
{
    /// <summary>
    /// In-place file encryption. Nothing is copied, zipped or duplicated.
    ///
    /// Locking: the file's bytes are overwritten with AES-256-CTR ciphertext (same length), and a
    /// 512-byte trailer is appended. The trailer holds a random per-file key, encrypted with the
    /// user's RSA public key, plus the original length.
    ///
    /// Crash safety: the trailer field <c>E</c> always means "bytes [0, E) are encrypted, the rest is
    /// plain". Locking moves E forward chunk by chunk; unlocking moves it back to 0. If the PC loses
    /// power halfway, unlocking still restores the file.
    /// </summary>
    internal static class LockedFile
    {
        public const string Extension = ".locked";
        private const int TrailerSize = 512;
        private const int Chunk = 8 << 20; // 8 MB
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("FLOCKv01");

        private const byte StateLocking = 1, StateLocked = 2, StateUnlocking = 3;
        private const int OffState = 1, OffNonce = 4, OffWrapLen = 12, OffWrap = 16, OffOrigLen = 272, OffE = 280, OffMagic = 504;

        private sealed class Trailer
        {
            public byte State;
            public byte[] Nonce;
            public byte[] WrappedKey;
            public long OrigLen;
            public long E;
        }

        public sealed class WrongKeyException : Exception
        {
            public WrongKeyException() : base("This file was locked with a different FileLocker key (another PC or another setup).") { }
        }

        /// <summary>True if the file carries a FileLocker trailer (fully or partly locked).</summary>
        public static bool IsLocked(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    return Read(fs) != null;
            }
            catch { return false; }
        }

        private static Trailer Read(FileStream fs)
        {
            long len = fs.Length;
            if (len < TrailerSize) return null;
            var b = new byte[TrailerSize];
            fs.Position = len - TrailerSize;
            ReadFull(fs, b, TrailerSize);
            for (int i = 0; i < Magic.Length; i++) if (b[OffMagic + i] != Magic[i]) return null;
            if (b[0] != 1) return null;
            var t = new Trailer
            {
                State = b[OffState],
                Nonce = Crypto.Slice(b, OffNonce, 8),
                OrigLen = BitConverter.ToInt64(b, OffOrigLen),
                E = BitConverter.ToInt64(b, OffE),
            };
            int wl = BitConverter.ToInt32(b, OffWrapLen);
            if (wl <= 0 || wl > 256 || t.OrigLen != len - TrailerSize || t.E < 0 || t.E > t.OrigLen) return null;
            t.WrappedKey = Crypto.Slice(b, OffWrap, wl);
            return t;
        }

        private static void WriteTrailer(FileStream fs, Trailer t)
        {
            var b = new byte[TrailerSize];
            b[0] = 1;
            b[OffState] = t.State;
            Buffer.BlockCopy(t.Nonce, 0, b, OffNonce, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(t.WrappedKey.Length), 0, b, OffWrapLen, 4);
            Buffer.BlockCopy(t.WrappedKey, 0, b, OffWrap, t.WrappedKey.Length);
            Buffer.BlockCopy(BitConverter.GetBytes(t.OrigLen), 0, b, OffOrigLen, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(t.E), 0, b, OffE, 8);
            Buffer.BlockCopy(Magic, 0, b, OffMagic, Magic.Length);
            fs.Position = t.OrigLen;
            fs.Write(b, 0, b.Length);
        }

        private static void WriteProgress(FileStream fs, Trailer t)
        {
            fs.Position = t.OrigLen + OffState;
            fs.WriteByte(t.State);
            fs.Position = t.OrigLen + OffE;
            fs.Write(BitConverter.GetBytes(t.E), 0, 8);
        }

        /// <summary>Encrypt a file in place with the public key. Returns false if it was already locked.</summary>
        public static bool Lock(string path, RSACryptoServiceProvider publicKey, Action<long> progress)
        {
            return WithFile(path, fs =>
            {
                var t = Read(fs);
                if (t != null)
                {
                    if (t.State == StateLocked) return false;
                    throw new IOException("This file was interrupted while being locked or unlocked. Unlock it first, then lock it again.");
                }
                var key = Crypto.Random(32);
                t = new Trailer
                {
                    State = StateLocking,
                    Nonce = Crypto.Random(8),
                    WrappedKey = publicKey.Encrypt(key, true),
                    OrigLen = fs.Length,
                    E = 0,
                };
                bool big = t.OrigLen > Chunk;
                WriteTrailer(fs, t);
                if (big) fs.Flush(true);

                var buf = new byte[(int)Math.Min(Chunk, Math.Max(t.OrigLen, 16))];
                using (var ctr = new Crypto.Ctr(key, t.Nonce))
                {
                    while (t.E < t.OrigLen)
                    {
                        int n = (int)Math.Min(Chunk, t.OrigLen - t.E);
                        fs.Position = t.E;
                        ReadFull(fs, buf, n);
                        ctr.Transform(buf, n, t.E);
                        fs.Position = t.E;
                        fs.Write(buf, 0, n);
                        if (big) fs.Flush(true);
                        t.E += n;
                        WriteProgress(fs, t);
                        if (big) fs.Flush(true);
                        progress?.Invoke(n);
                    }
                }
                t.State = StateLocked;
                WriteProgress(fs, t);
                fs.Flush(big);
                Array.Clear(key, 0, key.Length);
                return true;
            });
        }

        /// <summary>Decrypt a file in place with the private key. Returns false if it wasn't locked.</summary>
        public static bool Unlock(string path, RSACryptoServiceProvider privateKey, Action<long> progress)
        {
            return WithFile(path, fs =>
            {
                var t = Read(fs);
                if (t == null) return false;
                byte[] key;
                try { key = privateKey.Decrypt(t.WrappedKey, true); }
                catch (CryptographicException) { throw new WrongKeyException(); }

                bool big = t.OrigLen > Chunk;
                t.State = StateUnlocking;
                WriteProgress(fs, t);
                var buf = new byte[(int)Math.Min(Chunk, Math.Max(t.OrigLen, 16))];
                using (var ctr = new Crypto.Ctr(key, t.Nonce))
                {
                    // Walk backwards so the "[0,E) is encrypted" rule holds after every step.
                    while (t.E > 0)
                    {
                        long start = ((t.E - 1) / Chunk) * Chunk;
                        int n = (int)(t.E - start);
                        fs.Position = start;
                        ReadFull(fs, buf, n);
                        ctr.Transform(buf, n, start);
                        fs.Position = start;
                        fs.Write(buf, 0, n);
                        if (big) fs.Flush(true);
                        t.E = start;
                        WriteProgress(fs, t);
                        if (big) fs.Flush(true);
                        progress?.Invoke(n);
                    }
                }
                fs.SetLength(t.OrigLen);
                fs.Flush(big);
                Array.Clear(key, 0, key.Length);
                return true;
            });
        }

        /// <summary>Opens the file exclusively, keeping its timestamps and read-only flag intact.</summary>
        private static bool WithFile(string path, Func<FileStream, bool> work)
        {
            var info = new FileInfo(path);
            var attrs = info.Attributes;
            var created = info.CreationTimeUtc;
            var written = info.LastWriteTimeUtc;
            bool wasReadOnly = (attrs & FileAttributes.ReadOnly) != 0;
            if (wasReadOnly) File.SetAttributes(path, attrs & ~FileAttributes.ReadOnly);
            try
            {
                bool changed;
                try
                {
                    using (var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.None))
                        changed = work(fs);
                }
                catch (IOException ex) when (IsSharingViolation(ex))
                {
                    throw new IOException("The file is open in another program. Close it and try again.", ex);
                }
                if (changed)
                {
                    try { File.SetCreationTimeUtc(path, created); File.SetLastWriteTimeUtc(path, written); } catch { }
                }
                return changed;
            }
            finally
            {
                if (wasReadOnly) try { File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly); } catch { }
            }
        }

        private static bool IsSharingViolation(IOException ex)
        {
            int code = ex.HResult & 0xFFFF;
            return code == 32 || code == 33; // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
        }

        private static void ReadFull(Stream s, byte[] buf, int count)
        {
            int got = 0;
            while (got < count)
            {
                int r = s.Read(buf, got, count - got);
                if (r <= 0) throw new EndOfStreamException();
                got += r;
            }
        }
    }
}
