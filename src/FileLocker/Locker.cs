using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace FileLocker
{
    /// <summary>What the locking logic needs from the user interface.</summary>
    internal interface IUi
    {
        /// <summary>
        /// Ask for the PIN and return the private key blob, or null if cancelled.
        /// When <paramref name="fresh"/> is false a PIN typed in the last few minutes may be reused;
        /// when true the PIN must be typed now (used for removing a lock permanently).
        /// </summary>
        byte[] GetPrivateKey(bool fresh);
        void Status(string text);
        void Progress(long done, long total);
        void Error(string path, string message);
    }

    /// <summary>High-level lock/unlock operations on files and folders.</summary>
    internal sealed class Locker
    {
        private readonly IUi _ui;
        private RSACryptoServiceProvider _public, _private;
        private long _done, _total;

        public Locker(IUi ui) { _ui = ui; }

        private RSACryptoServiceProvider Public
        {
            get
            {
                if (_public == null)
                {
                    _public = new RSACryptoServiceProvider { PersistKeyInCsp = false };
                    _public.ImportCspBlob(Vault.Load().PublicKey);
                }
                return _public;
            }
        }

        /// <summary>Returns false if the user cancelled the PIN prompt.</summary>
        private bool _freshPin;

        private bool EnsurePrivate(bool fresh = false)
        {
            if (_private != null && (!fresh || _freshPin)) return true;
            var blob = _ui.GetPrivateKey(fresh);
            if (blob == null) return false;
            _private = new RSACryptoServiceProvider { PersistKeyInCsp = false };
            _private.ImportCspBlob(blob);
            if (fresh) _freshPin = true;
            return true;
        }

        public static string StripExtension(string path) =>
            path.EndsWith(LockedFile.Extension, StringComparison.OrdinalIgnoreCase)
                ? path.Substring(0, path.Length - LockedFile.Extension.Length)
                : path;

        // ------------------------------------------------------------------ lock

        public void Lock(string path)
        {
            path = Guard.Normalize(path);
            if (Directory.Exists(path)) LockFolder(path);
            else if (File.Exists(path)) { BeginWork(new[] { path }); if (LockFileAt(path) != null) Tracked.Add(StripExtension(path)); }
            else _ui.Error(path, "This file or folder no longer exists.");
        }

        private string LockFileAt(string path)
        {
            try
            {
                Guard.Check(path);
                var name = Path.GetFileName(path);
                if (IsSkippedSystemFile(name)) return null;
                bool hasExt = path.EndsWith(LockedFile.Extension, StringComparison.OrdinalIgnoreCase);
                if (hasExt && LockedFile.IsLocked(path)) { Unlocked.Remove(path); return path; }

                var target = path + LockedFile.Extension;
                if (File.Exists(target) || Directory.Exists(target))
                    throw new IOException("A file named \"" + Path.GetFileName(target) + "\" already exists next to it.");

                _ui.Status("Locking " + name);
                LockedFile.Lock(path, Public, n => Tick(n));
                File.Move(path, target);
                Unlocked.Remove(path);
                return target;
            }
            catch (Exception ex) { _ui.Error(path, ex.Message); return null; }
        }

        private void LockFolder(string dir)
        {
            try { Guard.Check(dir); }
            catch (Exception ex) { _ui.Error(dir, ex.Message); return; }

            _ui.Status("Looking inside " + Path.GetFileName(dir) + "…");
            var files = EnumerateFiles(dir)
                .Where(f => !IsSkippedSystemFile(Path.GetFileName(f)))
                .Where(f => !(f.EndsWith(LockedFile.Extension, StringComparison.OrdinalIgnoreCase) && LockedFile.IsLocked(f)))
                .ToList();
            BeginWork(files);
            foreach (var f in files) LockFileAt(f);
            Folder.Mark(dir);
            Unlocked.RemoveTree(dir);
            Tracked.AddFolder(dir);
            Shell.Refresh(dir);
        }

        // ------------------------------------------------------------------ unlock

        /// <summary>Unlock a file or folder. Returns the unlocked file path (for "open"), or null.</summary>
        public string Unlock(string path)
        {
            path = Guard.Normalize(path);
            if (Directory.Exists(path)) { UnlockFolder(path); return null; }
            if (!File.Exists(path)) { _ui.Error(path, "This file no longer exists."); return null; }
            if (!LockedFile.IsLocked(path))
            {
                // Already unlocked (e.g. a second double-click). Just strip a leftover extension.
                if (!path.EndsWith(LockedFile.Extension, StringComparison.OrdinalIgnoreCase)) return path;
                _ui.Error(path, "This file isn't locked by FileLocker.");
                return null;
            }
            if (!EnsurePrivate()) return null;
            BeginWork(new[] { path });
            var result = UnlockFileAt(path);
            if (result != null) Tracked.Add(StripExtension(path));
            return result;
        }

        private string UnlockFileAt(string path)
        {
            try
            {
                _ui.Status("Unlocking " + Path.GetFileName(path));
                LockedFile.Unlock(path, _private, n => Tick(n));
                var target = path.EndsWith(LockedFile.Extension, StringComparison.OrdinalIgnoreCase)
                    ? path.Substring(0, path.Length - LockedFile.Extension.Length)
                    : path;
                if (!string.Equals(target, path, StringComparison.OrdinalIgnoreCase))
                {
                    if (File.Exists(target) || Directory.Exists(target)) target = FreeName(target);
                    File.Move(path, target);
                }
                Unlocked.Add(target);
                return target;
            }
            catch (Exception ex) { _ui.Error(path, ex.Message); return null; }
        }

        /// <summary>Returns true if every file in the folder is now unlocked.</summary>
        private bool UnlockFolder(string dir, bool permanent = false)
        {
            _ui.Status("Looking inside " + Path.GetFileName(dir) + "…");
            var files = EnumerateFiles(dir).Where(f => LockedFile.IsLocked(f)).ToList();
            if (files.Count > 0 && !EnsurePrivate(permanent)) return false;
            BeginWork(files);
            int failed = 0;
            foreach (var f in files) if (UnlockFileAt(f) == null) failed++;
            if (failed == 0) Folder.Unmark(dir);
            Unlocked.RemoveTree(dir);
            if (!permanent)
            {
                Unlocked.Add(dir);
                Tracked.AddFolder(dir);
            }
            Shell.Refresh(dir);
            return failed == 0;
        }

        // ------------------------------------------------------------------ remove for good

        /// <summary>
        /// Unlock a file or folder and stop protecting it, so "Lock everything" won't lock it again.
        /// Always asks for the PIN, even if it was typed a minute ago.
        /// </summary>
        public void RemoveLock(string path)
        {
            path = Guard.Normalize(StripExtension(path));
            if (!EnsurePrivate(fresh: true)) return;

            if (Directory.Exists(path))
            {
                if (!UnlockFolder(path, permanent: true)) return; // keep it listed if something failed
                Tracked.RemoveTree(path);
                return;
            }

            var lockedPath = File.Exists(path + LockedFile.Extension) ? path + LockedFile.Extension
                           : File.Exists(path) && LockedFile.IsLocked(path) ? path
                           : null;
            if (lockedPath != null)
            {
                BeginWork(new[] { lockedPath });
                var result = UnlockFileAt(lockedPath);
                if (result == null) return;
                Unlocked.Remove(result);
            }
            Unlocked.Remove(path);
            Tracked.Remove(path);
            _ui.Status("The lock was removed from " + Path.GetFileName(path) + ".");
        }

        // ------------------------------------------------------------------ lock all

        /// <summary>Re-lock everything that was unlocked with FileLocker, and end the PIN session.</summary>
        public void LockAll()
        {
            Vault.SessionClear();
            var items = Unlocked.All();
            if (items.Count == 0) { _ui.Status("Nothing to lock. Everything is already locked."); return; }
            foreach (var item in items)
            {
                if (Directory.Exists(item)) LockFolder(item);
                else if (File.Exists(item)) { BeginWork(new[] { item }); if (LockFileAt(item) != null) Tracked.Add(item); }
                else Unlocked.Remove(item);
            }
        }

        // ------------------------------------------------------------------ helpers

        private void BeginWork(IEnumerable<string> files)
        {
            _done = 0;
            _total = 0;
            foreach (var f in files) try { _total += new FileInfo(f).Length; } catch { }
            _ui.Progress(0, _total);
        }

        private void Tick(long n) { _done += n; _ui.Progress(_done, _total); }

        private static bool IsSkippedSystemFile(string name) =>
            name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("thumbs.db", StringComparison.OrdinalIgnoreCase) ||
            name.Equals(Folder.BackupName, StringComparison.OrdinalIgnoreCase);

        private static string FreeName(string path)
        {
            var dir = Path.GetDirectoryName(path);
            var stem = Path.GetFileNameWithoutExtension(path);
            var ext = Path.GetExtension(path);
            for (int i = 1; ; i++)
            {
                var candidate = Path.Combine(dir, stem + (i == 1 ? " (unlocked)" : " (unlocked " + i + ")") + ext);
                if (!File.Exists(candidate) && !Directory.Exists(candidate)) return candidate;
            }
        }

        /// <summary>All files under a folder, without following junctions/symlinks, skipping unreadable folders.</summary>
        private static IEnumerable<string> EnumerateFiles(string root)
        {
            var stack = new Stack<string>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                var dir = stack.Pop();
                string[] files = null, dirs = null;
                try { files = Directory.GetFiles(dir); dirs = Directory.GetDirectories(dir); } catch { }
                if (files != null) foreach (var f in files) yield return f;
                if (dirs != null)
                    foreach (var d in dirs)
                    {
                        try { if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
                        stack.Push(d);
                    }
            }
        }
    }

    /// <summary>Gives locked folders a padlock icon via desktop.ini.</summary>
    internal static class Folder
    {
        public const string BackupName = "desktop.ini.filelocker-backup";
        private const string Section = "[FileLocker]";

        private static string IconPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "locked.ico");

        public static void Mark(string dir)
        {
            try
            {
                var ini = Path.Combine(dir, "desktop.ini");
                var backup = Path.Combine(dir, BackupName);
                bool hadReadOnly = (File.GetAttributes(dir) & FileAttributes.ReadOnly) != 0;
                if (File.Exists(ini))
                {
                    var existing = File.ReadAllText(ini);
                    if (existing.Contains(Section))
                        hadReadOnly = existing.Contains("HadReadOnly=1");
                    else if (!File.Exists(backup))
                    {
                        File.SetAttributes(ini, FileAttributes.Normal);
                        File.Move(ini, backup);
                        File.SetAttributes(backup, FileAttributes.Hidden | FileAttributes.System);
                    }
                    if (File.Exists(ini)) File.SetAttributes(ini, FileAttributes.Normal);
                }
                var text = "[.ShellClassInfo]\r\n" +
                           "IconResource=" + IconPath + ",0\r\n" +
                           "InfoTip=Locked with FileLocker\r\n" +
                           Section + "\r\n" +
                           "Locked=1\r\n" +
                           "HadReadOnly=" + (hadReadOnly ? "1" : "0") + "\r\n";
                File.WriteAllText(ini, text, Encoding.Unicode);
                File.SetAttributes(ini, FileAttributes.Hidden | FileAttributes.System);
                File.SetAttributes(dir, File.GetAttributes(dir) | FileAttributes.ReadOnly);
            }
            catch { /* the icon is cosmetic; the files themselves are locked */ }
        }

        public static bool IsMarked(string dir)
        {
            try
            {
                var ini = Path.Combine(dir, "desktop.ini");
                return File.Exists(ini) && File.ReadAllText(ini).Contains(Section);
            }
            catch { return false; }
        }

        public static void Unmark(string dir)
        {
            try
            {
                var ini = Path.Combine(dir, "desktop.ini");
                var backup = Path.Combine(dir, BackupName);
                if (!File.Exists(ini)) return;
                var text = File.ReadAllText(ini);
                if (!text.Contains(Section)) return;
                bool hadReadOnly = text.Contains("HadReadOnly=1");
                File.SetAttributes(ini, FileAttributes.Normal);
                File.Delete(ini);
                if (File.Exists(backup))
                {
                    File.SetAttributes(backup, FileAttributes.Normal);
                    File.Move(backup, ini);
                    File.SetAttributes(ini, FileAttributes.Hidden | FileAttributes.System);
                }
                else if (!hadReadOnly)
                    File.SetAttributes(dir, File.GetAttributes(dir) & ~FileAttributes.ReadOnly);
            }
            catch { }
        }
    }

    /// <summary>A list of paths stored one per line in the FileLocker data folder.</summary>
    internal sealed class PathList
    {
        private readonly string _file;
        public PathList(string fileName) { _file = fileName; }
        public string FilePath => Path.Combine(Vault.Dir, _file);

        public List<string> All()
        {
            try
            {
                return File.Exists(FilePath)
                    ? File.ReadAllLines(FilePath).Select(l => l.Trim()).Where(l => l.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                    : new List<string>();
            }
            catch { return new List<string>(); }
        }

        public void Save(IEnumerable<string> items)
        {
            try { Directory.CreateDirectory(Vault.Dir); File.WriteAllLines(FilePath, items); } catch { }
        }

        public bool Contains(string path) => All().Contains(path, StringComparer.OrdinalIgnoreCase);

        public void Add(string path)
        {
            var all = All();
            if (!all.Contains(path, StringComparer.OrdinalIgnoreCase)) { all.Add(path); Save(all); }
        }

        public void Remove(string path)
        {
            var all = All();
            if (all.RemoveAll(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase)) > 0) Save(all);
        }

        public static bool IsUnder(string path, string dir) =>
            path.StartsWith(dir.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);

        /// <summary>Removes the folder itself and everything inside it.</summary>
        public void RemoveTree(string dir)
        {
            var all = All();
            if (all.RemoveAll(p => string.Equals(p, dir, StringComparison.OrdinalIgnoreCase) || IsUnder(p, dir)) > 0) Save(all);
        }
    }

    /// <summary>Things unlocked with FileLocker, so "Lock everything" can lock them again.</summary>
    internal static class Unlocked
    {
        private static readonly PathList List = new PathList("unlocked.txt");
        public static string FilePath => List.FilePath;
        public static List<string> All() => List.All();
        public static void Add(string path) => List.Add(path);
        public static void Remove(string path) => List.Remove(path);
        public static void RemoveTree(string dir) => List.RemoveTree(dir);
        public static bool AnyUnder(string dir) => All().Any(p => string.Equals(p, dir, StringComparison.OrdinalIgnoreCase) || PathList.IsUnder(p, dir));
    }

    /// <summary>
    /// Everything the user has locked, shown in the FileLocker window. Items are stored by their
    /// normal name (without ".locked"), so an item keeps its identity whether it's locked or open.
    /// A file inside a tracked folder isn't listed separately.
    /// </summary>
    internal static class Tracked
    {
        public enum State { Locked, Open, PartlyOpen, Missing }

        private static readonly PathList List = new PathList("locked-items.txt");
        public static string FilePath => List.FilePath;
        public static List<string> All() => List.All();
        public static void Remove(string path) => List.Remove(path);
        public static void RemoveTree(string dir) => List.RemoveTree(dir);

        public static void Add(string path)
        {
            var all = All();
            if (all.Any(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase) || PathList.IsUnder(path, p))) return;
            all.Add(path);
            List.Save(all);
        }

        public static void AddFolder(string dir)
        {
            var all = All();
            if (all.Any(p => PathList.IsUnder(dir, p))) return; // already inside a tracked folder
            all.RemoveAll(p => PathList.IsUnder(p, dir));
            if (!all.Contains(dir, StringComparer.OrdinalIgnoreCase)) all.Add(dir);
            List.Save(all);
        }

        public static bool IsFolder(string path) => Directory.Exists(path);

        public static State StateOf(string path)
        {
            if (Directory.Exists(path))
            {
                if (!Folder.IsMarked(path)) return State.Open;
                return Unlocked.AnyUnder(path) ? State.PartlyOpen : State.Locked;
            }
            if (File.Exists(path + LockedFile.Extension)) return State.Locked;
            if (File.Exists(path)) return LockedFile.IsLocked(path) ? State.Locked : State.Open;
            return State.Missing;
        }

        /// <summary>The path to hand to "open": the .locked file if the file is locked.</summary>
        public static string CurrentPath(string path) =>
            !Directory.Exists(path) && File.Exists(path + LockedFile.Extension) ? path + LockedFile.Extension : path;
    }

    /// <summary>Tells Explorer to redraw icons.</summary>
    internal static class Shell
    {
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern void SHChangeNotify(int eventId, uint flags, string item1, IntPtr item2);

        private const int SHCNE_UPDATEDIR = 0x1000, SHCNE_UPDATEITEM = 0x2000;
        private const uint SHCNF_PATHW = 0x0005;

        public static void Refresh(string path)
        {
            try
            {
                SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, path, IntPtr.Zero);
                SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW, path, IntPtr.Zero);
                var parent = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(parent)) SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW, parent, IntPtr.Zero);
            }
            catch { }
        }
    }
}
