using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace FileLocker
{
    /// <summary>
    /// The FileLocker window: a plain list of everything you've locked, with big buttons.
    /// Actions run in a separate FileLocker process (the same one Explorer's right-click uses),
    /// so there's one tested path for locking and unlocking.
    /// </summary>
    internal sealed class MainForm : Form
    {
        private const int IconLocked = 0, IconOpen = 1, IconMissing = 2;

        private readonly ListView _list;
        private readonly Label _empty, _summary;
        private readonly Button _open, _relock, _remove, _lockAll;
        private readonly System.Windows.Forms.Timer _timer;
        private string _stamp = "";

        public MainForm()
        {
            AutoScaleDimensions = new SizeF(96f, 96f);
            AutoScaleMode = AutoScaleMode.Dpi;
            Text = "FileLocker";
            Font = new Font("Segoe UI", 10.5f);
            Icon = Ui.AppIcon;
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(900, 620);
            MinimumSize = new Size(680, 480);

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(18, 14, 18, 10) };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            // Header
            var header = Ui.Column();
            header.Controls.Add(new Label { Text = "Your locked files and folders", AutoSize = true, Font = new Font("Segoe UI Semibold", 15f), Margin = new Padding(0, 0, 0, 2) });
            _summary = new Label { AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(0, 0, 0, 10) };
            header.Controls.Add(_summary);

            // Top buttons
            var lockFile = Big("Lock a file…");
            var lockFolder = Big("Lock a folder…");
            _lockAll = Big("Lock everything now");
            lockFile.Click += (s, e) => PickFiles();
            lockFolder.Click += (s, e) => PickFolder();
            _lockAll.Click += (s, e) => Spawn("lockall", null);
            var top = Ui.Row(lockFile, lockFolder, _lockAll);
            top.Margin = new Padding(0, 0, 0, 10);

            // The list
            var icons = new ImageList { ColorDepth = ColorDepth.Depth32Bit };
            int px;
            using (var g = CreateGraphics()) px = (int)Math.Round(24 * g.DpiX / 96f);
            icons.ImageSize = new Size(px, px);
            icons.Images.Add(LoadIcon("locked.ico", SystemIcons.Shield, px));
            icons.Images.Add(LoadIcon("unlocked.ico", SystemIcons.Information, px));
            icons.Images.Add(SystemIcons.Warning.ToBitmap());

            _list = new ListView
            {
                View = View.Details, FullRowSelect = true, MultiSelect = true, HideSelection = false,
                Dock = DockStyle.Fill, SmallImageList = icons, HeaderStyle = ColumnHeaderStyle.Nonclickable,
                BorderStyle = BorderStyle.FixedSingle,
            };
            _list.Columns.Add("Name", 270);
            _list.Columns.Add("Status", 300);
            _list.Columns.Add("Where it is", 280);
            _list.SelectedIndexChanged += (s, e) => UpdateButtons();
            _list.DoubleClick += (s, e) => OpenSelected();
            _list.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter) OpenSelected();
                else if (e.KeyCode == Keys.Delete) RemoveSelected();
            };

            _empty = new Label
            {
                Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, ForeColor = SystemColors.GrayText,
                Font = new Font("Segoe UI", 12f), BackColor = SystemColors.Window, BorderStyle = BorderStyle.FixedSingle,
                Text = "Nothing is locked yet.\n\nClick \"Lock a file…\" or \"Lock a folder…\" above to start.",
            };
            var listArea = new Panel { Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 10) };
            listArea.Controls.Add(_list);
            listArea.Controls.Add(_empty);

            // Bottom buttons
            _open = Big("Open");
            _relock = Big("Lock again");
            _remove = Big("Remove lock…");
            _open.Click += (s, e) => OpenSelected();
            _relock.Click += (s, e) => RelockSelected();
            _remove.Click += (s, e) => RemoveSelected();
            var actions = Ui.Row(_open, _relock, _remove);
            actions.Margin = new Padding(0, 0, 0, 8);

            // Footer links
            var footer = Ui.Row(
                Link("Change PIN or password", ChangeSecret),
                Link("Forgot PIN?", () => { using (var d = new RecoveryDialog(Vault.Load())) d.ShowDialog(this); }),
                Link("How to use", () => MessageBox.Show(this, Ui.HowTo, "FileLocker", MessageBoxButtons.OK, MessageBoxIcon.Information)),
                Link("Check for updates", () => Updater.Check(this)),
                new Label { Text = "Version " + Updater.Current.ToString(3), AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(12, 3, 0, 0) });

            layout.Controls.Add(header, 0, 0);
            layout.Controls.Add(top, 0, 1);
            layout.Controls.Add(listArea, 0, 2);
            layout.Controls.Add(actions, 0, 3);
            layout.Controls.Add(footer, 0, 4);
            Controls.Add(layout);

            // Pick up changes made from Explorer (right-click, double-click) while this window is open.
            _timer = new System.Windows.Forms.Timer { Interval = 2000 };
            _timer.Tick += (s, e) => { if (Stamp() != _stamp) RefreshList(); };
            _timer.Start();
            Activated += (s, e) => RefreshList();
            Load += (s, e) => RefreshList();
        }

        private static Button Big(string text)
        {
            var b = Ui.Btn(text);
            b.MinimumSize = new Size(150, 40);
            b.Margin = new Padding(0, 0, 10, 0);
            return b;
        }

        private static LinkLabel Link(string text, Action onClick)
        {
            var l = new LinkLabel { Text = text, AutoSize = true, Margin = new Padding(0, 3, 16, 0) };
            l.LinkClicked += (s, e) => onClick();
            return l;
        }

        private static Image LoadIcon(string file, Icon fallback, int px)
        {
            try
            {
                var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, file);
                if (File.Exists(path)) using (var ic = new Icon(path, px, px)) return ic.ToBitmap();
            }
            catch { }
            return fallback.ToBitmap();
        }

        // ------------------------------------------------------------------ list

        private static string Stamp()
        {
            string T(string p) { try { return File.Exists(p) ? File.GetLastWriteTimeUtc(p).Ticks.ToString() : "-"; } catch { return "?"; } }
            return T(Tracked.FilePath) + "|" + T(Unlocked.FilePath) + "|" + T(AutoRelock.FilePath);
        }

        private sealed class Row
        {
            public string Path;
            public Tracked.State State;
            public bool IsFolder;
        }

        private void RefreshList()
        {
            _stamp = Stamp();
            var selected = new HashSet<string>(SelectedRows().Select(r => r.Path), StringComparer.OrdinalIgnoreCase);
            int locked = 0, open = 0;
            var watched = new HashSet<string>(AutoRelock.All().Select(e => e.Path), StringComparer.OrdinalIgnoreCase);
            _list.BeginUpdate();
            _list.Items.Clear();
            foreach (var path in Tracked.All().OrderBy(p => System.IO.Path.GetFileName(p), StringComparer.CurrentCultureIgnoreCase))
            {
                var row = new Row { Path = path, State = Tracked.StateOf(path), IsFolder = Directory.Exists(path) };
                string kind = row.IsFolder ? "folder" : "file";
                string status;
                int icon;
                switch (row.State)
                {
                    case Tracked.State.Locked: status = "Locked " + kind; icon = IconLocked; locked++; break;
                    case Tracked.State.PartlyOpen: status = "Some files open. They lock again when closed"; icon = IconOpen; open++; break;
                    case Tracked.State.Open:
                        status = watched.Contains(path) ? "Open. Locks again when you close it" : "Open. Click \"Lock again\" when done";
                        icon = IconOpen; open++; break;
                    default: status = "Can't find it (moved or deleted?)"; icon = IconMissing; break;
                }
                var item = new ListViewItem(System.IO.Path.GetFileName(path)) { Tag = row, ImageIndex = icon };
                item.SubItems.Add(status);
                item.SubItems.Add(System.IO.Path.GetDirectoryName(path) ?? "");
                if (row.State == Tracked.State.Missing) item.ForeColor = SystemColors.GrayText;
                if (row.State == Tracked.State.Open || row.State == Tracked.State.PartlyOpen) item.ForeColor = Color.FromArgb(21, 128, 61);
                item.Selected = selected.Contains(path);
                _list.Items.Add(item);
            }
            _list.EndUpdate();

            _empty.Visible = _list.Items.Count == 0;
            _list.Visible = !_empty.Visible;
            if (_list.Items.Count == 0) _summary.Text = "Lock a file or folder and it will appear here.";
            else
            {
                var parts = new List<string> { locked + " locked" };
                if (open > 0) parts.Add(open + " open. Click \"Lock everything now\" when you're done");
                _summary.Text = string.Join(" · ", parts);
            }
            _lockAll.Enabled = open > 0 || Unlocked.All().Count > 0;
            UpdateButtons();
        }

        private List<Row> SelectedRows() =>
            _list == null ? new List<Row>() : _list.SelectedItems.Cast<ListViewItem>().Select(i => (Row)i.Tag).ToList();

        private void UpdateButtons()
        {
            var rows = SelectedRows();
            _open.Enabled = rows.Any(r => r.State != Tracked.State.Missing);
            _relock.Enabled = rows.Any(r => r.State == Tracked.State.Open || r.State == Tracked.State.PartlyOpen);
            _remove.Enabled = rows.Count > 0;
        }

        // ------------------------------------------------------------------ actions

        private void OpenSelected()
        {
            var rows = SelectedRows();
            if (rows.Count == 0) return;
            if (rows.Count > 5 && MessageBox.Show(this, "Open all " + rows.Count + " items?", "FileLocker", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
            foreach (var r in rows)
            {
                switch (r.State)
                {
                    case Tracked.State.Locked:
                        Spawn("open", Tracked.CurrentPath(r.Path));
                        break;
                    case Tracked.State.Open:
                    case Tracked.State.PartlyOpen:
                        try
                        {
                            if (r.IsFolder) Process.Start("explorer.exe", "\"" + r.Path + "\"");
                            else Process.Start(new ProcessStartInfo(r.Path) { UseShellExecute = true });
                        }
                        catch (Exception ex) { MessageBox.Show(this, ex.Message, "FileLocker"); }
                        break;
                    default:
                        MessageBox.Show(this,
                            "FileLocker can't find \"" + Path.GetFileName(r.Path) + "\".\n\nIt may have been moved, renamed or deleted. " +
                            "To take it off this list, select it and click \"Remove lock…\".", "FileLocker", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        break;
                }
            }
        }

        private void RelockSelected()
        {
            foreach (var r in SelectedRows())
                if (r.State == Tracked.State.Open || r.State == Tracked.State.PartlyOpen) Spawn("lock", r.Path);
        }

        private void RemoveSelected()
        {
            var rows = SelectedRows();
            if (rows.Count == 0) return;
            var what = rows.Count == 1 ? "\"" + Path.GetFileName(rows[0].Path) + "\"" : "these " + rows.Count + " items";
            var answer = MessageBox.Show(this,
                "Remove the lock from " + what + " for good?\n\n" +
                "It will be unlocked and FileLocker will stop protecting it. Anyone using this computer will be able to open it.\n\n" +
                "You'll need to type your PIN or password.",
                "Remove lock", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes) return;
            foreach (var r in rows) Spawn("remove", r.Path);
        }

        private void PickFiles()
        {
            using (var d = new OpenFileDialog { Title = "Choose the file or files to lock", Multiselect = true, CheckFileExists = true })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                foreach (var f in d.FileNames) Spawn("lock", f);
            }
        }

        private void PickFolder()
        {
            using (var d = new FolderBrowserDialog { Description = "Choose the folder to lock. Everything inside it will be locked.", ShowNewFolderButton = false })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                Spawn("lock", d.SelectedPath);
            }
        }

        private void ChangeSecret()
        {
            var key = PinDialog.Ask(this, "to change your PIN or password");
            if (key == null) return;
            using (var d = new ChangeSecretDialog(Vault.Load(), key)) d.ShowDialog(this);
        }

        /// <summary>Runs "FileLocker.exe verb path". Several at once are merged into one window by the worker.</summary>
        private void Spawn(string verb, string path)
        {
            try
            {
                var args = path == null ? verb : verb + " \"" + path.TrimEnd('\\') + "\"";
                var p = Process.Start(new ProcessStartInfo(Application.ExecutablePath, args) { UseShellExecute = false });
                if (p == null) return;
                p.EnableRaisingEvents = true;
                p.Exited += (s, e) => { try { BeginInvoke(new Action(RefreshList)); } catch { } };
            }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "FileLocker"); }
        }
    }

    /// <summary>"Check for updates": asks GitHub for the newest release and installs it if you agree.</summary>
    internal static class Updater
    {
        private const string LatestApi = "https://api.github.com/repos/olamideba/filelocker/releases/latest";

        public static Version Current
        {
            get
            {
                var v = Assembly.GetExecutingAssembly().GetName().Version;
                return new Version(v.Major, v.Minor, Math.Max(v.Build, 0));
            }
        }

        public static void Check(Form owner)
        {
            owner.Cursor = Cursors.WaitCursor;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                string tag = null, url = null, error = null;
                try
                {
                    ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
                    var req = (HttpWebRequest)WebRequest.Create(LatestApi);
                    req.UserAgent = "FileLocker-updater";
                    req.Accept = "application/vnd.github+json";
                    req.Timeout = 15000;
                    string json;
                    using (var resp = req.GetResponse())
                    using (var sr = new StreamReader(resp.GetResponseStream())) json = sr.ReadToEnd();
                    tag = Regex.Match(json, "\"tag_name\"\\s*:\\s*\"v?([^\"]+)\"").Groups[1].Value;
                    url = Regex.Match(json, "\"browser_download_url\"\\s*:\\s*\"([^\"]+\\.exe)\"").Groups[1].Value;
                }
                catch (Exception ex) { error = ex.Message; }
                owner.BeginInvoke(new Action(() => { owner.Cursor = Cursors.Default; Offer(owner, tag, url, error); }));
            });
        }

        private static void Offer(Form owner, string tag, string url, string error)
        {
            if (error != null || !Version.TryParse(tag, out var latest) || string.IsNullOrEmpty(url))
            {
                MessageBox.Show(owner, "Couldn't check for updates. Make sure the computer is connected to the internet and try again." +
                    (error != null ? "\n\n(" + error + ")" : ""), "FileLocker", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            latest = new Version(latest.Major, latest.Minor, Math.Max(latest.Build, 0));
            if (latest <= Current)
            {
                MessageBox.Show(owner, "You have the latest version (" + Current.ToString(3) + ").", "FileLocker", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            var answer = MessageBox.Show(owner,
                "A new version of FileLocker is available.\n\nYou have: " + Current.ToString(3) + "\nNew version: " + latest.ToString(3) +
                "\n\nInstall it now? Your PIN, recovery key and locked files stay exactly as they are.",
                "FileLocker update", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
            if (answer != DialogResult.Yes) return;

            var dest = Path.Combine(Path.GetTempPath(), "FileLocker-Setup-" + latest.ToString(3) + ".exe");
            var oldTitle = owner.Text;
            owner.Text = "FileLocker: downloading the update…";
            owner.Cursor = Cursors.WaitCursor;
            var wc = new WebClient();
            wc.Headers.Add("User-Agent", "FileLocker-updater");
            wc.DownloadProgressChanged += (s, e) => owner.Text = "FileLocker: downloading the update… " + e.ProgressPercentage + "%";
            wc.DownloadFileCompleted += (s, e) =>
            {
                wc.Dispose();
                owner.Cursor = Cursors.Default;
                owner.Text = oldTitle;
                if (e.Error != null)
                {
                    MessageBox.Show(owner, "The download didn't finish. Try again later.\n\n(" + e.Error.Message + ")", "FileLocker");
                    return;
                }
                try
                {
                    Process.Start(new ProcessStartInfo(dest) { UseShellExecute = true });
                    Application.Exit(); // the installer replaces this program
                }
                catch (Exception ex) { MessageBox.Show(owner, ex.Message, "FileLocker"); }
            };
            wc.DownloadFileAsync(new Uri(url), dest);
        }
    }
}
