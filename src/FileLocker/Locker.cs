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
        /// <summary>Ask for the PIN (or reuse the session). Returns the private key blob, or null if cancelled.</summary>
        byte[] GetPrivateKey();
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
        private bool EnsurePrivate()
        {
            if (_private != null) return true;
            var blob = _ui.GetPrivateKey();
            if (blob == null) return false;
            _private = new RSACryptoServiceProvider { PersistKeyInCsp = false };
            _private.ImportCspBlob(blob);
            return true;
        }

        // ------------------------------------------------------------------ lock

        public void Lock(string path)
        {
            path = Guard.Normalize(path);
            if (Directory.Exists(path)) LockFolder(path);
            else if (File.Exists(path)) { BeginWork(new[] { path }); LockFileAt(path); }
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
            return UnlockFileAt(path);
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

        private void UnlockFolder(string dir)
        {
            _ui.Status("Looking inside " + Path.GetFileName(dir) + "…");
            var files = EnumerateFiles(dir).Where(f => LockedFile.IsLocked(f)).ToList();
            if (files.Count > 0 && !EnsurePrivate()) return;
            BeginWork(files);
            int failed = 0;
            foreach (var f in files) if (UnlockFileAt(f) == null) failed++;
            if (failed == 0) Folder.Unmark(dir);
            Unlocked.RemoveTree(dir);
            Unlocked.Add(dir);
            Shell.Refresh(dir);
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
                else if (File.Exists(item)) { BeginWork(new[] { item }); LockFileAt(item); }
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

    /// <summary>The list of things unlocked with FileLocker, so "Lock everything" can re-lock them.</summary>
    internal static class Unlocked
    {
        private static string ListPath => Path.Combine(Vault.Dir, "unlocked.txt");

        public static List<string> All()
        {
            try { return File.Exists(ListPath) ? File.ReadAllLines(ListPath).Where(l => l.Trim().Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList() : new List<string>(); }
            catch { return new List<string>(); }
        }

        private static void Save(IEnumerable<string> items)
        {
            try { Directory.CreateDirectory(Vault.Dir); File.WriteAllLines(ListPath, items); } catch { }
        }

        public static void Add(string path)
        {
            var all = All();
            if (!all.Contains(path, StringComparer.OrdinalIgnoreCase)) { all.Add(path); Save(all); }
        }

        public static void Remove(string path)
        {
            var all = All();
            if (all.RemoveAll(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase)) > 0) Save(all);
        }

        public static void RemoveTree(string dir)
        {
            var prefix = dir.TrimEnd('\\') + "\\";
            var all = All();
            if (all.RemoveAll(p => string.Equals(p, dir, StringComparison.OrdinalIgnoreCase) || p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) > 0) Save(all);
        }
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
