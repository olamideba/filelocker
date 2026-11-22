using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace FileLocker
{
    internal sealed class Request
    {
        public readonly string Verb, Path;
        public Request(string verb, string path) { Verb = verb; Path = path; }
    }

    internal static class Program
    {
        public const string RepoUrl = "https://github.com/olamideba/filelocker";
        private static readonly string[] Verbs = { "lock", "unlock", "open", "lockall", "remove" };

        private static string Suffix => Environment.UserName + "." + Process.GetCurrentProcess().SessionId;
        private static string MutexName => @"Local\FileLocker.Worker." + Suffix;
        internal static string PipeName => "FileLocker.Worker." + Suffix;

        // Usage:
        //   FileLocker.exe                 open the main window (or setup on first run)
        //   FileLocker.exe setup           first-time setup
        //   FileLocker.exe lock <path>     lock a file or folder
        //   FileLocker.exe unlock <path>   unlock a file or folder
        //   FileLocker.exe open <path>     unlock a file, then open it
        //   FileLocker.exe lockall         re-lock everything unlocked with FileLocker
        //   FileLocker.exe remove <path>   remove the lock for good (always asks for the PIN)
        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            try { Run(args); }
            catch (Exception ex)
            {
                MessageBox.Show("Something went wrong:\n\n" + ex.Message, "FileLocker", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void Run(string[] args)
        {
            var verb = args.Length > 0 ? args[0].Trim().TrimStart('-', '/').ToLowerInvariant() : "";

            if (verb == "" || verb == "setup")
            {
                if (!Vault.IsSetUp)
                {
                    Application.Run(new SetupForm());
                    if (!Vault.IsSetUp) return;
                }
                Application.Run(new MainForm());
                return;
            }
            if (!Verbs.Contains(verb))
            {
                MessageBox.Show("Unknown command: " + verb, "FileLocker");
                return;
            }
            var path = args.Length > 1 ? args[1] : null;
            if (verb != "lockall" && string.IsNullOrWhiteSpace(path)) return;

            if (!Vault.IsSetUp)
            {
                MessageBox.Show("FileLocker isn't set up yet. Let's choose your PIN or password first.", "FileLocker");
                Application.Run(new SetupForm());
                if (!Vault.IsSetUp) return;
            }

            var req = new Request(verb, path);

            // When several files are selected, Explorer starts one FileLocker per file. The first
            // one becomes the worker; the others hand their file to it and exit, so you see one
            // window and type your PIN once.
            using (var mutex = new Mutex(false, MutexName))
            {
                bool owned;
                while (true)
                {
                    owned = TryTake(mutex, 0);
                    if (owned) break;
                    if (Ipc.Send(req)) return;
                    owned = TryTake(mutex, 300);
                    if (owned) break;
                }
                try
                {
                    var form = new WorkerForm(req);
                    Ipc.StartServer(form.TryEnqueue);
                    Application.Run(form);
                }
                finally { mutex.ReleaseMutex(); }
            }
        }

        private static bool TryTake(Mutex m, int ms)
        {
            try { return m.WaitOne(ms); }
            catch (AbandonedMutexException) { return true; }
        }
    }

    /// <summary>Tiny named-pipe protocol: client sends "verb\tpath\n", server answers 'Y' if it took the job.</summary>
    internal static class Ipc
    {
        public static bool Send(Request r)
        {
            try
            {
                using (var c = new NamedPipeClientStream(".", Program.PipeName, PipeDirection.InOut))
                {
                    c.Connect(400);
                    var msg = Encoding.UTF8.GetBytes(r.Verb + "\t" + (r.Path ?? "") + "\n");
                    c.Write(msg, 0, msg.Length);
                    c.Flush();
                    return c.ReadByte() == 'Y';
                }
            }
            catch { return false; }
        }

        public static void StartServer(Func<Request, bool> accept)
        {
            var t = new Thread(() =>
            {
                while (true)
                {
                    try
                    {
                        using (var s = new NamedPipeServerStream(Program.PipeName, PipeDirection.InOut,
                                   NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte))
                        {
                            s.WaitForConnection();
                            var ms = new MemoryStream();
                            int b;
                            while ((b = s.ReadByte()) >= 0 && b != '\n') ms.WriteByte((byte)b);
                            var line = Encoding.UTF8.GetString(ms.ToArray());
                            int tab = line.IndexOf('\t');
                            bool ok = false;
                            if (tab > 0)
                            {
                                var path = line.Substring(tab + 1);
                                ok = accept(new Request(line.Substring(0, tab), path.Length > 0 ? path : null));
                            }
                            s.WriteByte((byte)(ok ? 'Y' : 'N'));
                            s.Flush();
                            try { s.WaitForPipeDrain(); } catch { }
                        }
                    }
                    catch { Thread.Sleep(50); }
                }
            });
            t.IsBackground = true;
            t.Start();
        }
    }
}
