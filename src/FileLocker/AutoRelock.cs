using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace FileLocker
{
    /// <summary>
    /// Locks things again by themselves once you're done with them.
    ///
    /// When a locked file or folder is opened (double-click, "Open"), it's added to a watch list and
    /// a small background FileLocker ("watch" mode) checks it every 2 seconds. Once nothing is using
    /// it for a few checks in a row, it's locked again. Locking needs no PIN (only the public key),
    /// so this happens silently.
    ///
    /// "In use" means any of:
    ///  * the program FileLocker started to open it is still running;
    ///  * some program still has the file open (Word, Excel, video players…);
    ///  * a window title still shows the file's name (Notepad, Photos, PDF readers…);
    ///  * for folders: an Explorer window is showing that folder (or a folder inside it).
    /// </summary>
    internal static class AutoRelock
    {
        public static readonly TimeSpan Grace = TimeSpan.FromSeconds(20); // time for the program to start
        public const int QuietChecksNeeded = 3;                            // ~6 seconds unused before locking
        public const int IntervalMs = 2000;

        public sealed class Entry
        {
            public string Path;
            public int Pid;
            public long AddedTicks;
        }

        public static string FilePath => System.IO.Path.Combine(Vault.Dir, "auto-relock.txt");

        private static Mutex ListMutex() => new Mutex(false, @"Local\FileLocker.AutoList." + Environment.UserName);

        private static List<Entry> Load()
        {
            var list = new List<Entry>();
            try
            {
                if (!File.Exists(FilePath)) return list;
                foreach (var line in File.ReadAllLines(FilePath))
                {
                    var parts = line.Split('\t');
                    if (parts.Length < 3 || parts[0].Length == 0) continue;
                    list.Add(new Entry { Path = parts[0], Pid = int.TryParse(parts[1], out var pid) ? pid : 0, AddedTicks = long.TryParse(parts[2], out var t) ? t : 0 });
                }
            }
            catch { }
            return list;
        }

        private static void Save(List<Entry> list)
        {
            try
            {
                Directory.CreateDirectory(Vault.Dir);
                File.WriteAllLines(FilePath, list.Select(e => e.Path + "\t" + e.Pid + "\t" + e.AddedTicks));
            }
            catch { }
        }

        private static T WithList<T>(Func<List<Entry>, T> f)
        {
            using (var m = ListMutex())
            {
                bool owned = false;
                try { owned = m.WaitOne(3000); } catch (AbandonedMutexException) { owned = true; }
                try { return f(Load()); }
                finally { if (owned) m.ReleaseMutex(); }
            }
        }

        public static List<Entry> All() => WithList(l => l);

        public static bool IsWatched(string path) => All().Any(e => string.Equals(e.Path, path, StringComparison.OrdinalIgnoreCase));

        /// <summary>Watch this path and lock it again when it's no longer in use.</summary>
        public static void Add(string path, int pid, DateTime? nowUtc = null)
        {
            WithList(l =>
            {
                l.RemoveAll(e => string.Equals(e.Path, path, StringComparison.OrdinalIgnoreCase));
                l.Add(new Entry { Path = path, Pid = pid, AddedTicks = (nowUtc ?? DateTime.UtcNow).Ticks });
                Save(l);
                return 0;
            });
        }

        public static void Remove(string path)
        {
            WithList(l =>
            {
                if (l.RemoveAll(e => string.Equals(e.Path, path, StringComparison.OrdinalIgnoreCase)) > 0) Save(l);
                return 0;
            });
        }

        /// <summary>
        /// One round of checks. <paramref name="quiet"/> counts consecutive "not in use" checks per
        /// path and must be kept between rounds. Returns how many items are still being watched.
        /// </summary>
        public static int Pass(DateTime nowUtc, Func<Entry, bool> inUse, Dictionary<string, int> quiet)
        {
            var entries = All();
            var unlocked = new HashSet<string>(Unlocked.All(), StringComparer.OrdinalIgnoreCase);
            var finished = new List<Entry>();

            foreach (var e in entries)
            {
                // Locked again by hand, or lock removed for good: nothing left to do.
                if (!unlocked.Contains(e.Path)) { finished.Add(e); continue; }
                if (!File.Exists(e.Path) && !Directory.Exists(e.Path)) { Unlocked.Remove(e.Path); finished.Add(e); continue; }

                bool busy;
                try { busy = nowUtc - new DateTime(e.AddedTicks, DateTimeKind.Utc) < Grace || inUse(e); }
                catch { busy = true; }
                if (busy) { quiet[e.Path] = 0; continue; }

                quiet.TryGetValue(e.Path, out var q);
                quiet[e.Path] = ++q;
                if (q < QuietChecksNeeded) continue;

                if (Relock(e.Path)) { finished.Add(e); quiet.Remove(e.Path); }
                else quiet[e.Path] = 0; // something's still open inside; try again later
            }

            return WithList(l =>
            {
                if (finished.Count > 0)
                {
                    l.RemoveAll(x => finished.Any(f => string.Equals(f.Path, x.Path, StringComparison.OrdinalIgnoreCase) && f.AddedTicks == x.AddedTicks));
                    Save(l);
                }
                return l.Count;
            });
        }

        private sealed class SilentUi : IUi
        {
            public int Errors;
            public byte[] GetPrivateKey(bool fresh) => null; // locking never needs the PIN
            public void Status(string text) { }
            public void Progress(long done, long total) { }
            public void Error(string path, string message) { Errors++; }
        }

        /// <summary>Lock a path again. Returns true if everything in it is locked.</summary>
        private static bool Relock(string path)
        {
            var ui = new SilentUi();
            bool isFolder = Directory.Exists(path);
            new Locker(ui).Lock(path);
            if (ui.Errors == 0) return true;
            if (isFolder) Unlocked.Add(path); // some file inside is still open: keep the folder on the list
            return false;
        }

        /// <summary>The background loop ("FileLocker.exe watch"). Ends a little while after the list is empty.</summary>
        public static void RunWatcher()
        {
            var quiet = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int emptyRounds = 0;
            while (emptyRounds < 5)
            {
                int left;
                try
                {
                    var probe = All().Count > 0 ? Probe.Snapshot() : null;
                    left = probe == null ? 0 : Pass(DateTime.UtcNow, probe.InUse, quiet);
                }
                catch { left = 1; }
                emptyRounds = left == 0 ? emptyRounds + 1 : 0;
                Thread.Sleep(IntervalMs);
            }
        }
    }

    /// <summary>Works out whether a file or folder is still being used. Built fresh each round.</summary>
    internal sealed class Probe
    {
        private List<string> _titles = new List<string>();
        private List<string> _explorerFolders = new List<string>();

        public static Probe Snapshot()
        {
            var p = new Probe();
            p._titles = WindowTitles();
            p._explorerFolders = ExplorerFolders();
            return p;
        }

        public bool InUse(AutoRelock.Entry e)
        {
            if (e.Pid > 0 && ProcessAlive(e.Pid)) return true;
            if (Directory.Exists(e.Path))
            {
                foreach (var f in _explorerFolders)
                    if (string.Equals(f, e.Path, StringComparison.OrdinalIgnoreCase) || PathList.IsUnder(f, e.Path)) return true;
                // A file from the folder shown in some program's title bar.
                var names = SafeFiles(e.Path, 3000);
                return names.Any(TitleMentions);
            }
            return HeldOpen(e.Path) || TitleMentions(e.Path);
        }

        private bool TitleMentions(string filePath)
        {
            var name = Path.GetFileName(filePath);
            var stem = Path.GetFileNameWithoutExtension(filePath);
            var key = stem.Length >= 3 ? stem : name;
            if (key.Length < 3) return false;
            return _titles.Any(t => t.IndexOf(key, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static IEnumerable<string> SafeFiles(string dir, int max)
        {
            try { return Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Where(f => !f.EndsWith(LockedFile.Extension, StringComparison.OrdinalIgnoreCase)).Take(max).ToList(); }
            catch { return new string[0]; }
        }

        public static bool ProcessAlive(int pid)
        {
            try { using (var p = Process.GetProcessById(pid)) return !p.HasExited; }
            catch { return false; }
        }

        /// <summary>True if another program has the file open in a way that stops it being changed.</summary>
        public static bool HeldOpen(string path)
        {
            try
            {
                using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete)) { }
                return false;
            }
            catch (IOException) { return File.Exists(path); }
            catch { return false; }
        }

        // ---------------------------------------------------------------- windows

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
        [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
        [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr hWnd, StringBuilder sb, int max);
        [DllImport("user32.dll")] private static extern int GetWindowTextLength(IntPtr hWnd);
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);

        private static List<string> WindowTitles()
        {
            var titles = new List<string>();
            uint me = (uint)Process.GetCurrentProcess().Id;
            try
            {
                EnumWindows((h, l) =>
                {
                    if (!IsWindowVisible(h)) return true;
                    int len = GetWindowTextLength(h);
                    if (len <= 0) return true;
                    GetWindowThreadProcessId(h, out var pid);
                    if (pid == me) return true;
                    var sb = new StringBuilder(len + 1);
                    GetWindowText(h, sb, sb.Capacity);
                    titles.Add(sb.ToString());
                    return true;
                }, IntPtr.Zero);
            }
            catch { }
            return titles;
        }

        /// <summary>Folders currently shown in File Explorer windows.</summary>
        private static List<string> ExplorerFolders()
        {
            var result = new List<string>();
            object shell = null, windows = null;
            try
            {
                var t = Type.GetTypeFromProgID("Shell.Application");
                if (t == null) return result;
                shell = Activator.CreateInstance(t);
                windows = t.InvokeMember("Windows", BindingFlags.InvokeMethod, null, shell, null);
                var wt = windows.GetType();
                int count = (int)wt.InvokeMember("Count", BindingFlags.GetProperty, null, windows, null);
                for (int i = 0; i < count; i++)
                {
                    object w = null;
                    try
                    {
                        w = wt.InvokeMember("Item", BindingFlags.InvokeMethod, null, windows, new object[] { i });
                        if (w == null) continue;
                        var url = w.GetType().InvokeMember("LocationURL", BindingFlags.GetProperty, null, w, null) as string;
                        if (!string.IsNullOrEmpty(url) && url.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
                            result.Add(Guard.Normalize(new Uri(url).LocalPath));
                    }
                    catch { }
                    finally { if (w != null && Marshal.IsComObject(w)) Marshal.ReleaseComObject(w); }
                }
            }
            catch { }
            finally
            {
                if (windows != null && Marshal.IsComObject(windows)) Marshal.ReleaseComObject(windows);
                if (shell != null && Marshal.IsComObject(shell)) Marshal.ReleaseComObject(shell);
            }
            return result;
        }
    }
}
