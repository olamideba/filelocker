using System;
using System.IO;

namespace FileLocker
{
    /// <summary>Refuses to lock places that would break Windows or lock the user out.</summary>
    internal static class Guard
    {
        public sealed class BlockedException : Exception
        {
            public BlockedException(string msg) : base(msg) { }
        }

        public static string Normalize(string path)
        {
            var full = Path.GetFullPath(path);
            var root = Path.GetPathRoot(full);
            if (full.Length > root.Length) full = full.TrimEnd('\\', '/');
            return full;
        }

        private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

        private static bool Under(string path, string dir)
        {
            if (string.IsNullOrEmpty(dir)) return false;
            dir = Normalize(dir);
            return Same(path, dir) || path.StartsWith(dir.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
        }

        public static void Check(string path)
        {
            var p = Normalize(path);
            var root = Path.GetPathRoot(p);
            if (Same(p, root) || Same(p + "\\", root))
                throw new BlockedException("Whole drives can't be locked. Lock a folder inside the drive instead.");

            string F(Environment.SpecialFolder f) => Environment.GetFolderPath(f);

            // Anywhere inside these is off-limits.
            string[] forbiddenTrees =
            {
                F(Environment.SpecialFolder.Windows),
                F(Environment.SpecialFolder.ProgramFiles),
                F(Environment.SpecialFolder.ProgramFilesX86),
                F(Environment.SpecialFolder.CommonApplicationData),
                F(Environment.SpecialFolder.ApplicationData),
                F(Environment.SpecialFolder.LocalApplicationData),
                AppDomain.CurrentDomain.BaseDirectory,
                Environment.GetEnvironmentVariable("ProgramW6432"),
            };
            foreach (var t in forbiddenTrees)
                if (Under(p, t)) throw new BlockedException("System and program folders can't be locked:\n" + p);

            // These exact folders are off-limits, but folders inside them are fine.
            var profile = F(Environment.SpecialFolder.UserProfile);
            string[] forbiddenExact =
            {
                profile,
                F(Environment.SpecialFolder.Desktop),
                F(Environment.SpecialFolder.DesktopDirectory),
                F(Environment.SpecialFolder.MyDocuments),
                F(Environment.SpecialFolder.MyPictures),
                F(Environment.SpecialFolder.MyMusic),
                F(Environment.SpecialFolder.MyVideos),
                string.IsNullOrEmpty(profile) ? null : Path.Combine(profile, "Downloads"),
                Environment.GetEnvironmentVariable("OneDrive"),
                Path.GetDirectoryName(profile), // C:\Users
            };
            foreach (var e in forbiddenExact)
                if (!string.IsNullOrEmpty(e) && Same(p, Normalize(e)))
                    throw new BlockedException("This whole folder can't be locked (Windows needs it). Lock a folder inside it instead:\n" + p);
        }
    }
}
