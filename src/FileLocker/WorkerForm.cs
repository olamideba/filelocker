using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace FileLocker
{
    /// <summary>The small progress window shown while locking/unlocking. Processes a queue of requests.</summary>
    internal sealed class WorkerForm : Form, IUi
    {
        private const int IdleMs = 700; // wait this long for more files from a multi-selection before closing

        private readonly Queue<Request> _queue = new Queue<Request>();
        private bool _closing, _cancelled, _keepOpen;
        private Request _current;
        private readonly Label _status;
        private readonly ProgressBar _bar;
        private readonly TextBox _errors;
        private readonly Button _close;
        private int _lastPercent = -1;
        private int _errorCount;

        public WorkerForm(Request first)
        {
            _queue.Enqueue(first);
            Ui.Setup(this, "FileLocker");
            var col = Ui.Column();
            _status = Ui.Text("Starting…", 420);
            _bar = new ProgressBar { Width = 420, Height = 18, Margin = new Padding(0, 0, 0, 10) };
            _errors = new TextBox
            {
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Width = 420, Height = 120,
                Visible = false, Margin = new Padding(0, 0, 0, 10), BackColor = SystemColors.Window,
            };
            _close = Ui.Btn("Close");
            _close.Visible = false;
            _close.Click += (s, e) => Close();
            col.Controls.AddRange(new Control[] { _status, _bar, _errors, _close });
            Controls.Add(col);
            CancelButton = _close;
            Shown += (s, e) => new Thread(WorkLoop) { IsBackground = true }.Start();
            FormClosing += (s, e) =>
            {
                // Never close mid-file; the work finishes in seconds and the window closes itself.
                lock (_queue) { if (!_closing) e.Cancel = true; }
            };
        }

        /// <summary>Called from the pipe thread when another FileLocker hands over a file.</summary>
        public bool TryEnqueue(Request r)
        {
            lock (_queue)
            {
                if (_closing) return false;
                _queue.Enqueue(r);
                Monitor.PulseAll(_queue);
                return true;
            }
        }

        private void WorkLoop()
        {
            var locker = new Locker(this);
            while (true)
            {
                Request r;
                lock (_queue)
                {
                    if (_queue.Count == 0) Monitor.Wait(_queue, IdleMs);
                    if (_queue.Count == 0) { _closing = true; break; }
                    r = _queue.Dequeue();
                }
                _current = r;
                try { Handle(locker, r); }
                catch (Exception ex) { Error(r.Path, ex.Message); }
            }
            BeginInvoke(new Action(Finish));
        }

        private void Handle(Locker locker, Request r)
        {
            switch (r.Verb)
            {
                case "lock":
                    locker.Lock(r.Path);
                    break;
                case "unlock":
                    if (!_cancelled) locker.Unlock(r.Path);
                    break;
                case "open":
                    if (_cancelled) break;
                    var p = locker.Unlock(r.Path);
                    if (p != null && File.Exists(p))
                    {
                        try { Process.Start(new ProcessStartInfo(p) { UseShellExecute = true }); }
                        catch (Exception ex) { Error(p, "Unlocked, but Windows couldn't open it: " + ex.Message); }
                    }
                    break;
                case "lockall":
                    locker.LockAll();
                    break;
            }
        }

        private void Finish()
        {
            if (_errorCount == 0 && !_keepOpen) { Close(); return; }
            _bar.Visible = false;
            if (_errorCount > 0)
                _status.Text = _errorCount == 1 ? "One item needs attention:" : _errorCount + " items need attention:";
            _close.Visible = true;
            _close.Focus();
            Activate();
        }

        // ---------------------------------------------------------------- IUi

        public byte[] GetPrivateKey()
        {
            if (_cancelled) return null;
            var cached = Vault.SessionGet();
            if (cached != null) return cached;
            byte[] key = null;
            Invoke(new Action(() =>
            {
                var what = _current?.Path != null ? Path.GetFileName(_current.Path) : "your files";
                key = PinDialog.Ask(this, what);
            }));
            if (key == null) _cancelled = true;
            else Vault.SessionSet(key);
            return key;
        }

        public void Status(string text)
        {
            BeginInvoke(new Action(() =>
            {
                _status.Text = text;
                if (text.StartsWith("Nothing to lock")) { _keepOpen = true; }
            }));
        }

        public void Progress(long done, long total)
        {
            int pct = total <= 0 ? 100 : (int)Math.Min(100, done * 100 / total);
            if (pct == _lastPercent) return;
            _lastPercent = pct;
            BeginInvoke(new Action(() => _bar.Value = pct));
        }

        public void Error(string path, string message)
        {
            Interlocked.Increment(ref _errorCount);
            BeginInvoke(new Action(() =>
            {
                _errors.Visible = true;
                _errors.AppendText((path != null ? Path.GetFileName(path) + ": " : "") + message.Replace("\n", " ") + Environment.NewLine);
            }));
        }
    }
}
