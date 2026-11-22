using System;
using System.Security.Cryptography;
using System.Text;

namespace FileLocker
{
    /// <summary>Low-level crypto helpers: AES-256-CTR keystream, authenticated wrapping, key derivation.</summary>
    internal static class Crypto
    {
        public static byte[] Random(int n)
        {
            var b = new byte[n];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            return b;
        }

        /// <summary>
        /// AES-256 in counter mode. Each 16-byte block at file offset <c>16*i</c> is XORed with
        /// AES(key, nonce8 || bigEndian64(i)). Because the keystream depends only on the offset,
        /// any chunk can be processed independently, in place, and XOR is its own inverse.
        /// </summary>
        public sealed class Ctr : IDisposable
        {
            private readonly ICryptoTransform _ecb;
            private readonly Aes _aes;
            private readonly byte[] _nonce;
            private byte[] _counter = new byte[0];
            private byte[] _stream = new byte[0];

            public Ctr(byte[] key, byte[] nonce8)
            {
                _aes = Aes.Create();
                _aes.Mode = CipherMode.ECB;
                _aes.Padding = PaddingMode.None;
                _aes.Key = key;
                _ecb = _aes.CreateEncryptor();
                _nonce = nonce8;
            }

            /// <summary>XOR <paramref name="count"/> bytes of buf with the keystream for absolute offset <paramref name="offset"/> (must be a multiple of 16).</summary>
            public unsafe void Transform(byte[] buf, int count, long offset)
            {
                if (count <= 0) return;
                if ((offset & 15) != 0) throw new ArgumentException("offset must be 16-byte aligned");
                int blocks = (count + 15) / 16;
                int len = blocks * 16;
                if (_counter.Length < len) { _counter = new byte[len]; _stream = new byte[len]; }
                long first = offset / 16;
                fixed (byte* c = _counter)
                {
                    ulong n = BitConverter.ToUInt64(_nonce, 0);
                    for (int i = 0; i < blocks; i++)
                    {
                        byte* p = c + i * 16;
                        *(ulong*)p = n;
                        ulong idx = (ulong)(first + i);
                        for (int k = 0; k < 8; k++) p[8 + k] = (byte)(idx >> (56 - 8 * k));
                    }
                }
                _ecb.TransformBlock(_counter, 0, len, _stream, 0);
                fixed (byte* d = buf)
                fixed (byte* s = _stream)
                {
                    int i = 0;
                    for (; i + 8 <= count; i += 8) *(ulong*)(d + i) ^= *(ulong*)(s + i);
                    for (; i < count; i++) d[i] ^= s[i];
                }
            }

            public void Dispose() { _ecb.Dispose(); _aes.Dispose(); }
        }

        /// <summary>Derive a 32-byte key from a secret with PBKDF2-HMAC-SHA256.</summary>
        public static byte[] Derive(string secret, byte[] salt, int iterations)
        {
            using (var kdf = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(secret), salt, iterations, HashAlgorithmName.SHA256))
                return kdf.GetBytes(32);
        }

        private static byte[] SubKey(byte[] key, string label)
        {
            using (var h = new HMACSHA256(key)) return h.ComputeHash(Encoding.ASCII.GetBytes(label));
        }

        /// <summary>Encrypt-then-MAC: returns nonce(16) || ciphertext || HMAC-SHA256(32).</summary>
        public static byte[] Wrap(byte[] key, byte[] data)
        {
            var nonce = Random(16);
            var ct = (byte[])data.Clone();
            using (var ctr = new Ctr(SubKey(key, "enc"), Slice(nonce, 0, 8))) ctr.Transform(ct, ct.Length, 0);
            var body = Concat(nonce, ct);
            byte[] tag;
            using (var h = new HMACSHA256(SubKey(key, "mac"))) tag = h.ComputeHash(body);
            return Concat(body, tag);
        }

        /// <summary>Reverse of <see cref="Wrap"/>. Returns null when the key is wrong or data was altered.</summary>
        public static byte[] Unwrap(byte[] key, byte[] blob)
        {
            if (blob == null || blob.Length < 48) return null;
            var body = Slice(blob, 0, blob.Length - 32);
            var tag = Slice(blob, blob.Length - 32, 32);
            byte[] expect;
            using (var h = new HMACSHA256(SubKey(key, "mac"))) expect = h.ComputeHash(body);
            int diff = 0;
            for (int i = 0; i < 32; i++) diff |= expect[i] ^ tag[i];
            if (diff != 0) return null;
            var ct = Slice(body, 16, body.Length - 16);
            using (var ctr = new Ctr(SubKey(key, "enc"), Slice(body, 0, 8))) ctr.Transform(ct, ct.Length, 0);
            return ct;
        }

        private const string B32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I to avoid confusion

        /// <summary>A human-friendly 160-bit recovery key, e.g. ABCD-EFGH-... (8 groups of 4).</summary>
        public static string NewRecoveryKey()
        {
            var bytes = Random(20);
            var sb = new StringBuilder();
            int buffer = 0, bits = 0, count = 0;
            foreach (var b in bytes)
            {
                buffer = (buffer << 8) | b; bits += 8;
                while (bits >= 5)
                {
                    if (count > 0 && count % 4 == 0) sb.Append('-');
                    sb.Append(B32[(buffer >> (bits - 5)) & 31]); bits -= 5; count++;
                }
            }
            return sb.ToString();
        }

        public static string NormalizeRecoveryKey(string s)
        {
            var sb = new StringBuilder();
            foreach (var c in (s ?? "").ToUpperInvariant())
                if (B32.IndexOf(c) >= 0) sb.Append(c); // dashes, spaces etc. are ignored
            return sb.ToString();
        }

        public static byte[] Slice(byte[] a, int start, int len)
        {
            var r = new byte[len];
            Buffer.BlockCopy(a, start, r, 0, len);
            return r;
        }

        public static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }
    }
}
