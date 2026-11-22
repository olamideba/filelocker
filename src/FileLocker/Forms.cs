using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace FileLocker
{
    /// <summary>Shared look and layout helpers. Everything uses auto-sizing flow layouts so text never gets cut off.</summary>
    internal static class Ui
    {
        public static readonly Font Base = new Font("Segoe UI", 10f);
        public static readonly Font Heading = new Font("Segoe UI Semibold", 13f);
        private static Icon _icon;

        public static Icon AppIcon
        {
            get
            {
                if (_icon == null) try { _icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
                return _icon;
            }
        }

        public static void Setup(Form f, string title)
        {
            f.AutoScaleDimensions = new SizeF(96f, 96f);
            f.AutoScaleMode = AutoScaleMode.Dpi;
            f.Text = title;
            f.Font = Base;
            f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.MaximizeBox = false;
            f.MinimizeBox = false;
            f.StartPosition = FormStartPosition.CenterScreen;
            f.AutoSize = true;
            f.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            f.Padding = new Padding(18);
            f.Icon = AppIcon;
            f.ShowInTaskbar = true;
        }

        public static FlowLayoutPanel Column() => new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(0),
        };

        public static FlowLayoutPanel Row(params Control[] cs)
        {
            var r = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.LeftToRight, WrapContents = false, AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(0, 4, 0, 4),
            };
            r.Controls.AddRange(cs);
            return r;
        }

        public static Label Text(string s, int width = 400) => new Label
        {
            Text = s, AutoSize = true, MaximumSize = new Size(width, 0), Margin = new Padding(0, 0, 0, 10),
        };

        public static Label Title(string s) => new Label
        {
            Text = s, AutoSize = true, Font = Heading, Margin = new Padding(0, 0, 0, 10),
        };

        public static Label ErrorLabel() => new Label
        {
            AutoSize = true, MaximumSize = new Size(400, 0), ForeColor = Color.Firebrick, Margin = new Padding(0, 0, 0, 6),
        };

        public static Button Btn(string text) => new Button
        {
            Text = text, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, MinimumSize = new Size(96, 32),
            Padding = new Padding(8, 2, 8, 2), Margin = new Padding(0, 0, 8, 0),
        };

        public static TextBox SecretBox() => new TextBox { UseSystemPasswordChar = true, Width = 280, Margin = new Padding(0, 0, 0, 8) };

        public static string HowTo =>
            "How to use FileLocker\n\n" +
            "LOCK SOMETHING\n" +
            "In the FileLocker window, click \"Lock a file…\" or \"Lock a folder…\".\n" +
            "Or right-click the file or folder and choose \"Lock with FileLocker\" " +
            "(on Windows 11, click \"Show more options\" first).\n\n" +
            "OPEN SOMETHING LOCKED\n" +
            "Double-click it, in the FileLocker window or in your folders, and type your PIN.\n\n" +
            "LOCK IT AGAIN WHEN YOU'RE DONE\n" +
            "Things you open stay open until you lock them again. Click \"Lock everything now\".\n\n" +
            "REMOVE A LOCK FOR GOOD\n" +
            "In the FileLocker window, select it and click \"Remove lock…\". You'll need your PIN.\n\n" +
            "FileLocker asks for your PIN every time something locked is opened. It never remembers it.";
    }

    /// <summary>"PIN or password" picker with an entry box and a confirmation box.</summary>
    internal sealed class SecretPanel : FlowLayoutPanel
    {
        private readonly RadioButton _pin, _pwd;
        private readonly TextBox _a, _b;
        private readonly Label _la, _lb;

        public SecretPanel(string currentKind = "pin")
        {
            FlowDirection = FlowDirection.TopDown;
            WrapContents = false;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Margin = new Padding(0);
            _pin = new RadioButton { Text = "PIN (numbers only, at least 6 digits)", AutoSize = true, Checked = currentKind == "pin" };
            _pwd = new RadioButton { Text = "Password (at least 8 characters)", AutoSize = true, Checked = currentKind != "pin", Margin = new Padding(3, 0, 3, 10) };
            _la = new Label { AutoSize = true, Margin = new Padding(0, 0, 0, 2) };
            _lb = new Label { AutoSize = true, Margin = new Padding(0, 0, 0, 2) };
            _a = Ui.SecretBox();
            _b = Ui.SecretBox();
            _pin.CheckedChanged += (s, e) => Relabel();
            _a.KeyPress += Digits;
            _b.KeyPress += Digits;
            Controls.AddRange(new Control[] { _pin, _pwd, _la, _a, _lb, _b });
            Relabel();
        }

        private void Digits(object sender, KeyPressEventArgs e)
        {
            if (_pin.Checked && !char.IsControl(e.KeyChar) && !char.IsDigit(e.KeyChar)) e.Handled = true;
        }

        private void Relabel()
        {
            _la.Text = _pin.Checked ? "New PIN" : "New password";
            _lb.Text = _pin.Checked ? "Type the PIN again" : "Type the password again";
            _a.Clear(); _b.Clear();
        }

        public string Kind => _pin.Checked ? "pin" : "password";
        public string Secret => _a.Text;
        public void FocusFirst() => _a.Focus();

        /// <summary>Returns an error message, or null if the entries are fine.</summary>
        public string Check()
        {
            var err = Vault.ValidateSecret(Kind, _a.Text);
            if (err != null) return err;
            if (_a.Text != _b.Text) return Kind == "pin" ? "The two PINs don't match." : "The two passwords don't match.";
            return null;
        }
    }

    /// <summary>Asks for the PIN/password and returns the private key.</summary>
    internal sealed class PinDialog : Form
    {
        public byte[] Result;
        private readonly Vault _v;
        private readonly TextBox _box;
        private readonly Label _err;
        private readonly Button _ok;
        private int _fails;

        /// <param name="purpose">Shown under the title, e.g. "to unlock report.docx".</param>
        public static byte[] Ask(IWin32Window owner, string purpose)
        {
            using (var d = new PinDialog(Vault.Load(), purpose))
                return d.ShowDialog(owner) == DialogResult.OK ? d.Result : null;
        }

        private PinDialog(Vault v, string what)
        {
            _v = v;
            Ui.Setup(this, "FileLocker");
            TopMost = true;
            bool pin = v.Kind == "pin";
            var col = Ui.Column();
            _box = Ui.SecretBox();
            if (pin) _box.KeyPress += (s, e) => { if (!char.IsControl(e.KeyChar) && !char.IsDigit(e.KeyChar)) e.Handled = true; };
            _err = Ui.ErrorLabel();
            _ok = Ui.Btn("Unlock");
            var cancel = Ui.Btn("Cancel");
            cancel.DialogResult = DialogResult.Cancel;
            _ok.Click += (s, e) => TryOk();
            var forgot = new LinkLabel { Text = "Forgot it? Use your recovery key", AutoSize = true, Margin = new Padding(0, 10, 0, 0) };
            forgot.LinkClicked += (s, e) => Forgot();
            col.Controls.AddRange(new Control[]
            {
                Ui.Title(pin ? "Enter your PIN" : "Enter your password"),
                Ui.Text(what),
                _box, _err, Ui.Row(_ok, cancel), forgot,
            });
            Controls.Add(col);
            AcceptButton = _ok;
            CancelButton = cancel;
            Shown += (s, e) => { Activate(); _box.Focus(); };
        }

        private void TryOk()
        {
            if (_box.Text.Length == 0) return;
            Cursor = Cursors.WaitCursor;
            _ok.Enabled = false;
            _err.Text = "Checking…";
            _err.ForeColor = SystemColors.GrayText;
            Refresh();
            var key = _v.TryUnlock(_box.Text);
            Cursor = Cursors.Default;
            _err.ForeColor = Color.Firebrick;
            if (key != null) { Result = key; DialogResult = DialogResult.OK; return; }

            _fails++;
            _box.Clear();
            _box.Focus();
            if (_fails % 5 == 0)
            {
                _err.Text = "Too many wrong tries. Wait 30 seconds.";
                var t = new Timer { Interval = 30000 };
                t.Tick += (s, e) => { t.Stop(); t.Dispose(); _ok.Enabled = true; _err.Text = ""; };
                t.Start();
            }
            else
            {
                _err.Text = _v.Kind == "pin" ? "Wrong PIN. Try again." : "Wrong password. Try again.";
                _ok.Enabled = true;
            }
        }

        private void Forgot()
        {
            using (var d = new RecoveryDialog(_v))
            {
                TopMost = false;
                if (d.ShowDialog(this) == DialogResult.OK) { Result = d.Result; DialogResult = DialogResult.OK; }
                TopMost = true;
            }
        }
    }

    /// <summary>Use the recovery key to set a new PIN/password.</summary>
    internal sealed class RecoveryDialog : Form
    {
        public byte[] Result;

        public RecoveryDialog(Vault v)
        {
            Ui.Setup(this, "FileLocker: recovery");
            var col = Ui.Column();
            var key = new TextBox { Width = 400, Font = new Font("Consolas", 11f), CharacterCasing = CharacterCasing.Upper, Margin = new Padding(0, 0, 0, 12) };
            var secret = new SecretPanel(v.Kind);
            var err = Ui.ErrorLabel();
            var ok = Ui.Btn("Set new PIN");
            var cancel = Ui.Btn("Cancel");
            cancel.DialogResult = DialogResult.Cancel;
            ok.Click += (s, e) =>
            {
                var blob = v.TryRecover(key.Text);
                if (blob == null) { err.Text = "That recovery key isn't right. Check each character."; return; }
                var problem = secret.Check();
                if (problem != null) { err.Text = problem; return; }
                v.SetSecret(blob, secret.Kind, secret.Secret);
                Result = blob;
                MessageBox.Show(this, "Done. Use your new " + (secret.Kind == "pin" ? "PIN" : "password") + " from now on.", "FileLocker");
                DialogResult = DialogResult.OK;
            };
            col.Controls.AddRange(new Control[]
            {
                Ui.Title("Use your recovery key"),
                Ui.Text("Type the recovery key you saved during setup (dashes are optional). Then choose a new PIN or password."),
                key, secret, err, Ui.Row(ok, cancel),
            });
            Controls.Add(col);
            AcceptButton = ok;
            CancelButton = cancel;
        }
    }

    /// <summary>Change the PIN/password (needs the current one).</summary>
    internal sealed class ChangeSecretDialog : Form
    {
        public ChangeSecretDialog(Vault v, byte[] privateKey)
        {
            Ui.Setup(this, "FileLocker: change PIN or password");
            var col = Ui.Column();
            var secret = new SecretPanel(v.Kind);
            var err = Ui.ErrorLabel();
            var ok = Ui.Btn("Save");
            var cancel = Ui.Btn("Cancel");
            cancel.DialogResult = DialogResult.Cancel;
            ok.Click += (s, e) =>
            {
                var problem = secret.Check();
                if (problem != null) { err.Text = problem; return; }
                v.SetSecret(privateKey, secret.Kind, secret.Secret);
                MessageBox.Show(this, "Saved. Your files stay locked. Use the new one from now on.\nYour recovery key hasn't changed.", "FileLocker");
                DialogResult = DialogResult.OK;
            };
            col.Controls.AddRange(new Control[] { Ui.Title("Choose a new PIN or password"), secret, err, Ui.Row(ok, cancel) });
            Controls.Add(col);
            AcceptButton = ok;
            CancelButton = cancel;
            Shown += (s, e) => secret.FocusFirst();
        }
    }

    /// <summary>First-run setup: choose PIN/password, then save the recovery key.</summary>
    internal sealed class SetupForm : Form
    {
        private readonly FlowLayoutPanel _col;

        public SetupForm()
        {
            Ui.Setup(this, "FileLocker setup");
            _col = Ui.Column();
            Controls.Add(_col);
            ShowChooseSecret();
        }

        private void ShowChooseSecret()
        {
            var secret = new SecretPanel();
            var err = Ui.ErrorLabel();
            var create = Ui.Btn("Continue");
            create.Click += (s, e) =>
            {
                var problem = secret.Check();
                if (problem != null) { err.Text = problem; return; }
                Cursor = Cursors.WaitCursor;
                create.Enabled = false;
                string recovery;
                try { recovery = Vault.Create(secret.Kind, secret.Secret); }
                finally { Cursor = Cursors.Default; }
                ShowRecovery(recovery);
            };
            _col.Controls.AddRange(new Control[]
            {
                Ui.Title("Welcome to FileLocker"),
                Ui.Text("Choose how you'll unlock your files. You'll type this every time you open a locked file or folder."),
                secret, err, create,
            });
            AcceptButton = create;
            Shown += (s, e) => secret.FocusFirst();
        }

        private void ShowRecovery(string recovery)
        {
            _col.SuspendLayout();
            _col.Controls.Clear();
            var box = new TextBox
            {
                Text = recovery, ReadOnly = true, Width = 420, Font = new Font("Consolas", 12f, FontStyle.Bold),
                BackColor = SystemColors.Window, Margin = new Padding(0, 0, 0, 8), TextAlign = HorizontalAlignment.Center,
            };
            var copy = Ui.Btn("Copy");
            copy.Click += (s, e) => { Clipboard.SetText(recovery); copy.Text = "Copied"; };
            var save = Ui.Btn("Save as file…");
            save.Click += (s, e) =>
            {
                using (var d = new SaveFileDialog { FileName = "FileLocker recovery key.txt", Filter = "Text file|*.txt" })
                {
                    if (d.ShowDialog(this) != DialogResult.OK) return;
                    File.WriteAllText(d.FileName,
                        "FileLocker recovery key\r\n\r\n" + recovery + "\r\n\r\n" +
                        "Use this if you forget your PIN or password: double-click any locked file, " +
                        "click \"Forgot it? Use your recovery key\" and type it in.\r\n" +
                        "Keep it somewhere safe and NOT on the same computer.\r\n");
                    save.Text = "Saved";
                }
            };
            var check = new CheckBox { Text = "I've written down or saved my recovery key", AutoSize = true, Margin = new Padding(0, 12, 0, 12) };
            var done = Ui.Btn("Finish");
            done.Enabled = false;
            check.CheckedChanged += (s, e) => done.Enabled = check.Checked;
            done.Click += (s, e) => Close(); // the main FileLocker window opens next
            _col.Controls.AddRange(new Control[]
            {
                Ui.Title("Save your recovery key"),
                Ui.Text("If you forget your PIN or password, this key is the ONLY way to get your files back. " +
                        "Nobody, including the makers of FileLocker, can recover them without it.", 420),
                box, Ui.Row(copy, save), check, done,
            });
            _col.ResumeLayout();
            AcceptButton = null;
        }
    }
}
