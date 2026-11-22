using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace FileLocker.Tests
{
    /// <summary>Self-contained checks run by CI on a real Windows machine. Exit code 0 = all passed.</summary>
    internal static class Program
    {
        private static int _failed, _passed;

        private static void Check(bool ok, string name)
        {
            if (ok) { _passed++; Console.WriteLine("  ok   " + name); }
            else { _failed++; Console.WriteLine("  FAIL " + name); }
        }

        private static int Main(string[] args)
        {
            var root = Path.Combine(args.Length > 0 ? args[0] : Directory.GetCurrentDirectory(), "fl-test-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(root);
            try
            {
                Run("crypto wrap/unwrap", CryptoTests);
                Run("recovery key format", RecoveryKeyTests);
                Run("file lock/unlock round trips", () => FileTests(root));
                Run("interrupted lock recovers", () => InterruptedTests(root));
                Run("vault + folder lock/unlock", () => FolderTests(root));
                Run("guard blocks system paths", GuardTests);
                Run("tracking + remove lock for good", () => TrackingTests(root));
            }
            finally
            {
                try { Directory.Delete(root, true); } catch { }
            }
            Console.WriteLine();
            Console.WriteLine(_passed + " passed, " + _failed + " failed");
            return _failed == 0 ? 0 : 1;
        }

        private static void Run(string name, Action a)
        {
            Console.WriteLine(name);
            try { a(); }
            catch (Exception ex) { _failed++; Console.WriteLine("  FAIL threw " + ex); }
        }

        private static void CryptoTests()
        {
            var key = Crypto.Random(32);
            var data = Crypto.Random(1234);
            var blob = Crypto.Wrap(key, data);
            Check(Crypto.Unwrap(key, blob)?.SequenceEqual(data) == true, "wrap round trip");
            Check(Crypto.Unwrap(Crypto.Random(32), blob) == null, "wrong key rejected");
            blob[20] ^= 1;
            Check(Crypto.Unwrap(key, blob) == null, "tampered data rejected");

            // CTR: transforming in two aligned pieces equals one pass, and twice restores.
            var buf = Crypto.Random(100);
            var orig = (byte[])buf.Clone();
            var nonce = Crypto.Random(8);
            using (var c = new Crypto.Ctr(key, nonce)) c.Transform(buf, 100, 0);
            var whole = (byte[])buf.Clone();
            var a = Crypto.Slice(orig, 0, 48);
            var b = Crypto.Slice(orig, 48, 52);
            using (var c = new Crypto.Ctr(key, nonce)) { c.Transform(a, 48, 0); c.Transform(b, 52, 48); }
            Check(Crypto.Concat(a, b).SequenceEqual(whole), "ctr is offset-addressable");
            using (var c = new Crypto.Ctr(key, nonce)) c.Transform(buf, 100, 0);
            Check(buf.SequenceEqual(orig), "ctr twice restores");
        }

        private static void RecoveryKeyTests()
        {
            var k = Crypto.NewRecoveryKey();
            Check(k.Length == 39 && k.Split('-').Length == 8, "format XXXX-…(8 groups): " + k);
            Check(Crypto.NormalizeRecoveryKey(k.ToLowerInvariant().Replace("-", " ")) == k.Replace("-", ""), "normalizes case and separators");
        }

        private static (RSACryptoServiceProvider pub, RSACryptoServiceProvider priv) NewKeys()
        {
            var rsa = new RSACryptoServiceProvider(2048) { PersistKeyInCsp = false };
            var pub = new RSACryptoServiceProvider { PersistKeyInCsp = false };
            pub.ImportCspBlob(rsa.ExportCspBlob(false));
            return (pub, rsa);
        }

        private static byte[] Hash(string path)
        {
            using (var s = File.OpenRead(path)) using (var h = SHA256.Create()) return h.ComputeHash(s);
        }

        private static void FileTests(string root)
        {
            var (pub, priv) = NewKeys();
            var (_, otherPriv) = NewKeys();
            const int MB = 1 << 20;
            long[] sizes = { 0, 1, 15, 16, 17, 4096, 8 * MB - 1, 8 * MB, 8 * MB + 1, 20 * MB + 123 };
            foreach (var size in sizes)
            {
                var p = Path.Combine(root, "f" + size + ".bin");
                File.WriteAllBytes(p, Crypto.Random((int)size));
                var before = Hash(p);
                var mtime = File.GetLastWriteTimeUtc(p);

                var sw = Stopwatch.StartNew();
                Check(LockedFile.Lock(p, pub, null), size + "B: lock");
                var lockMs = sw.ElapsedMilliseconds;
                Check(new FileInfo(p).Length == size + 512, size + "B: grows only by 512-byte trailer");
                Check(LockedFile.IsLocked(p), size + "B: detected as locked");
                Check(!LockedFile.Lock(p, pub, null), size + "B: locking twice is a no-op");

                bool threw = false;
                try { LockedFile.Unlock(p, otherPriv, null); } catch (LockedFile.WrongKeyException) { threw = true; }
                Check(threw, size + "B: wrong key refused");
                Check(LockedFile.IsLocked(p), size + "B: still locked after wrong key");

                sw.Restart();
                Check(LockedFile.Unlock(p, priv, null), size + "B: unlock");
                Check(Hash(p).SequenceEqual(before), size + "B: identical after unlock (lock " + lockMs + "ms, unlock " + sw.ElapsedMilliseconds + "ms)");
                Check(File.GetLastWriteTimeUtc(p) == mtime, size + "B: modified date preserved");
                Check(!LockedFile.IsLocked(p), size + "B: no longer locked");
            }

            // Encrypted bytes must differ from the original.
            var q = Path.Combine(root, "zeros.bin");
            File.WriteAllBytes(q, new byte[4096]);
            LockedFile.Lock(q, pub, null);
            var raw = File.ReadAllBytes(q);
            Check(raw.Take(4096).Any(x => x != 0), "ciphertext is not the plaintext");
            LockedFile.Unlock(q, priv, null);
            Check(File.ReadAllBytes(q).All(x => x == 0), "zeros restored");

            // Read-only files keep their flag.
            var ro = Path.Combine(root, "ro.txt");
            File.WriteAllText(ro, "hello");
            File.SetAttributes(ro, FileAttributes.ReadOnly);
            LockedFile.Lock(ro, pub, null);
            Check((File.GetAttributes(ro) & FileAttributes.ReadOnly) != 0, "read-only kept while locked");
            LockedFile.Unlock(ro, priv, null);
            File.SetAttributes(ro, FileAttributes.Normal);
            Check(File.ReadAllText(ro) == "hello", "read-only file restored");

            // A file open in another program is refused cleanly.
            var busy = Path.Combine(root, "busy.txt");
            File.WriteAllText(busy, "busy");
            bool refused = false;
            using (File.Open(busy, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                try { LockedFile.Lock(busy, pub, null); } catch (IOException) { refused = true; }
            }
            Check(refused && !LockedFile.IsLocked(busy) && File.ReadAllText(busy) == "busy", "file in use is left untouched");
        }

        private static void InterruptedTests(string root)
        {
            var (pub, priv) = NewKeys();
            const int MB = 1 << 20;
            var p = Path.Combine(root, "interrupted.bin");
            var data = Crypto.Random(20 * MB);
            File.WriteAllBytes(p, data);

            // Abort the lock after the first 8 MB chunk (simulates a power cut).
            int calls = 0;
            try { LockedFile.Lock(p, pub, n => { if (++calls == 1) throw new OperationCanceledException(); }); }
            catch (OperationCanceledException) { }
            Check(LockedFile.IsLocked(p), "half-locked file is detected");
            bool refused = false;
            try { LockedFile.Lock(p, pub, null); } catch (IOException) { refused = true; }
            Check(refused, "re-lock of half-locked file asks to unlock first");
            Check(LockedFile.Unlock(p, priv, null), "half-locked file unlocks");
            Check(File.ReadAllBytes(p).SequenceEqual(data), "half-locked file fully restored");

            // Abort an unlock halfway.
            LockedFile.Lock(p, pub, null);
            calls = 0;
            try { LockedFile.Unlock(p, priv, n => { if (++calls == 1) throw new OperationCanceledException(); }); }
            catch (OperationCanceledException) { }
            Check(LockedFile.Unlock(p, priv, null), "half-unlocked file finishes unlocking");
            Check(File.ReadAllBytes(p).SequenceEqual(data), "half-unlocked file fully restored");
        }

        private sealed class FakeUi : IUi
        {
            public byte[] Key;
            public int Prompts, FreshPrompts;
            public readonly List<string> Errors = new List<string>();
            public byte[] GetPrivateKey(bool fresh) { Prompts++; if (fresh) FreshPrompts++; return Key; }
            public void Status(string text) { }
            public void Progress(long done, long total) { }
            public void Error(string path, string message) { Errors.Add(path + ": " + message); Console.WriteLine("    (ui error) " + path + ": " + message); }
        }

        private static void FolderTests(string root)
        {
            if (!Vault.IsSetUp) Vault.Create("pin", "123456");
            var v = Vault.Load();
            var key = v.TryUnlock("123456");
            Check(key != null, "vault unlocks with right PIN");
            Check(v.TryUnlock("654321") == null, "vault refuses wrong PIN");

            var dir = Path.Combine(root, "My Folder");
            var sub = Path.Combine(dir, "sub dir");
            Directory.CreateDirectory(sub);
            var files = new Dictionary<string, byte[]>
            {
                [Path.Combine(dir, "a.txt")] = Crypto.Random(10),
                [Path.Combine(dir, "photo.jpg")] = Crypto.Random(300000),
                [Path.Combine(sub, "b.docx")] = Crypto.Random(5000),
                [Path.Combine(sub, "empty.dat")] = new byte[0],
            };
            foreach (var kv in files) File.WriteAllBytes(kv.Key, kv.Value);

            var ui = new FakeUi { Key = key };
            var locker = new Locker(ui);
            locker.Lock(dir);
            Check(ui.Errors.Count == 0, "folder lock had no errors");
            foreach (var f in files.Keys)
            {
                Check(!File.Exists(f) && File.Exists(f + ".locked"), "locked + renamed: " + Path.GetFileName(f));
                Check(LockedFile.IsLocked(f + ".locked"), "encrypted: " + Path.GetFileName(f));
            }
            Check(File.Exists(Path.Combine(dir, "desktop.ini")), "folder got padlock desktop.ini");
            Check(File.ReadAllText(Path.Combine(dir, "desktop.ini")).Contains("locked.ico"), "desktop.ini points at padlock icon");

            // Locking again is harmless.
            locker.Lock(dir);
            Check(ui.Errors.Count == 0 && !File.Exists(Path.Combine(dir, "a.txt.locked.locked")), "re-locking a locked folder is a no-op");

            // Open a single file inside (like double-click), then lock everything.
            var one = Path.Combine(dir, "a.txt");
            var opened = new Locker(ui).Unlock(one + ".locked");
            Check(opened == one && File.ReadAllBytes(one).SequenceEqual(files[one]), "single file unlocks to original name and content");
            Check(Unlocked.All().Contains(one, StringComparer.OrdinalIgnoreCase), "unlocked file is remembered");
            new Locker(ui).LockAll();
            Check(File.Exists(one + ".locked") && !File.Exists(one), "lock everything re-locks it");
            Check(!Unlocked.All().Contains(one, StringComparer.OrdinalIgnoreCase), "and forgets it");

            // Unlock the whole folder.
            new Locker(ui).Unlock(dir);
            Check(ui.Errors.Count == 0, "folder unlock had no errors");
            foreach (var kv in files)
                Check(File.Exists(kv.Key) && File.ReadAllBytes(kv.Key).SequenceEqual(kv.Value), "restored: " + Path.GetFileName(kv.Key));
            Check(!File.Exists(Path.Combine(dir, "desktop.ini")), "padlock removed from folder");
            Check((File.GetAttributes(dir) & FileAttributes.ReadOnly) == 0, "folder read-only flag restored");

            // Cancelled PIN prompt leaves files locked.
            locker.Lock(dir);
            var cancelUi = new FakeUi { Key = null };
            new Locker(cancelUi).Unlock(dir);
            Check(files.Keys.All(f => File.Exists(f + ".locked")), "cancelled PIN keeps everything locked");
            new Locker(ui).Unlock(dir);
            Unlocked.RemoveTree(dir);
        }

        private static void TrackingTests(string root)
        {
            if (!Vault.IsSetUp) Vault.Create("pin", "123456");
            var key = Vault.Load().TryUnlock("123456");
            var dir = Path.Combine(root, "Tracked Folder");
            Directory.CreateDirectory(Path.Combine(dir, "inner"));
            var inFolder = Path.Combine(dir, "inner", "secret.txt");
            File.WriteAllText(inFolder, "inside");
            var loose = Path.Combine(root, "loose.txt");
            File.WriteAllText(loose, "loose");

            var ui = new FakeUi { Key = key };
            new Locker(ui).Lock(loose);
            Check(Tracked.All().Contains(loose, StringComparer.OrdinalIgnoreCase), "locked file is listed");
            Check(Tracked.StateOf(loose) == Tracked.State.Locked, "listed file shows Locked");
            Check(Tracked.CurrentPath(loose) == loose + ".locked", "open target is the .locked file");

            new Locker(ui).Lock(dir);
            Check(Tracked.All().Contains(dir, StringComparer.OrdinalIgnoreCase), "locked folder is listed");
            Check(!Tracked.All().Any(p => p.StartsWith(dir + "\\", StringComparison.OrdinalIgnoreCase)), "files inside a listed folder aren't listed separately");
            Check(Tracked.StateOf(dir) == Tracked.State.Locked, "folder shows Locked");

            // Opening a file inside the folder: folder shows partly open, file not listed on its own.
            new Locker(ui).Unlock(inFolder + ".locked");
            Check(Tracked.StateOf(dir) == Tracked.State.PartlyOpen, "folder shows partly open");
            Check(!Tracked.All().Contains(inFolder, StringComparer.OrdinalIgnoreCase), "opened inner file still not listed separately");
            new Locker(ui).LockAll();
            Check(Tracked.StateOf(dir) == Tracked.State.Locked, "lock everything returns folder to Locked");

            // Opening a listed file keeps it listed (as Open).
            new Locker(ui).Unlock(loose + ".locked");
            Check(Tracked.StateOf(loose) == Tracked.State.Open, "opened file shows Open and stays listed");

            // Remove for good: cancelled PIN changes nothing.
            var cancel = new FakeUi { Key = null };
            new Locker(cancel).RemoveLock(dir);
            Check(Tracked.StateOf(dir) == Tracked.State.Locked && Tracked.All().Contains(dir, StringComparer.OrdinalIgnoreCase), "cancelled PIN: folder stays locked and listed");

            // Remove for good always asks for a fresh PIN.
            var removeUi = new FakeUi { Key = key };
            var remover = new Locker(removeUi);
            remover.RemoveLock(dir);
            remover.RemoveLock(loose);
            Check(removeUi.FreshPrompts == 1, "remove asks for the PIN fresh (once per batch)");
            Check(File.ReadAllText(inFolder) == "inside" && !Folder.IsMarked(dir), "removed folder is fully unlocked");
            Check(File.ReadAllText(loose) == "loose", "removed file is unlocked");
            bool Mine(string p) => string.Equals(p, dir, StringComparison.OrdinalIgnoreCase) || p.StartsWith(dir + "\\", StringComparison.OrdinalIgnoreCase) || string.Equals(p, loose, StringComparison.OrdinalIgnoreCase);
            Check(!Tracked.All().Any(Mine), "removed items are off the list");
            Check(!Unlocked.All().Any(Mine), "removed items won't be re-locked");
            new Locker(ui).LockAll();
            Check(!File.Exists(loose + ".locked") && File.Exists(loose), "lock everything leaves removed items alone");

            // A moved/deleted item shows as missing and can be removed from the list.
            var gone = Path.Combine(root, "gone.txt");
            File.WriteAllText(gone, "x");
            new Locker(ui).Lock(gone);
            File.Delete(gone + ".locked");
            Check(Tracked.StateOf(gone) == Tracked.State.Missing, "deleted item shows Can't find");
            new Locker(new FakeUi { Key = key }).RemoveLock(gone);
            Check(!Tracked.All().Contains(gone, StringComparer.OrdinalIgnoreCase), "missing item can be taken off the list");
        }

        private static void GuardTests()
        {
            bool Blocked(string p) { try { Guard.Check(p); return false; } catch (Guard.BlockedException) { return true; } }
            Check(Blocked(@"C:\"), "drive root");
            Check(Blocked(Environment.GetFolderPath(Environment.SpecialFolder.Windows)), "Windows folder");
            Check(Blocked(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32")), "inside Windows");
            Check(Blocked(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)), "Program Files");
            Check(Blocked(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)), "user profile");
            Check(Blocked(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)), "Documents itself");
            Check(!Blocked(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Private")), "folder inside Documents allowed");
            Check(Blocked(Vault.Dir), "FileLocker's own key folder");
        }
    }
}
