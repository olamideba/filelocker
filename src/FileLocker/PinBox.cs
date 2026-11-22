using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace FileLocker
{
    /// <summary>
    /// A row of boxes, one per PIN digit, that fill with a dot as you type, so it's obvious how many
    /// digits are still needed. Takes digits, Backspace and Ctrl+V. Raises <see cref="Completed"/>
    /// when every box is filled.
    /// </summary>
    internal sealed class PinBox : Control
    {
        private string _value = "";
        private int _slots;
        private readonly int _maxLength;

        public event EventHandler ValueChanged;
        public event EventHandler Completed;

        /// <param name="slots">How many boxes to draw.</param>
        /// <param name="maxLength">How many digits are accepted (more than slots grows the row; for old, longer PINs).</param>
        public PinBox(int slots = 6, int maxLength = 6)
        {
            _slots = slots;
            _maxLength = Math.Max(slots, maxLength);
            SetStyle(ControlStyles.Selectable | ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            TabStop = true;
            Cursor = Cursors.IBeam;
            Margin = new Padding(0, 0, 0, 8);
            UpdateSize();
        }

        public string Value => _value;
        public int Slots => _slots;

        public void Clear() => Set("");

        private int Box => (int)(Font.Height * 2.0);
        private int Gap => Math.Max(6, Font.Height / 3);

        private void UpdateSize() => Size = new Size(_slots * Box + (_slots - 1) * Gap + 2, (int)(Box * 1.15) + 2);

        protected override void OnFontChanged(EventArgs e) { base.OnFontChanged(e); UpdateSize(); }

        private void Set(string v)
        {
            _value = v;
            if (_value.Length > _slots) { _slots = _value.Length; UpdateSize(); }
            Invalidate();
            ValueChanged?.Invoke(this, EventArgs.Empty);
            if (_value.Length == _slots) Completed?.Invoke(this, EventArgs.Empty);
        }

        protected override bool IsInputKey(Keys keyData) =>
            (keyData & Keys.KeyCode) == Keys.Back || base.IsInputKey(keyData);

        protected override void OnKeyPress(KeyPressEventArgs e)
        {
            if (char.IsDigit(e.KeyChar) && _value.Length < _maxLength) { Set(_value + e.KeyChar); e.Handled = true; }
            else if (e.KeyChar == '\b') { if (_value.Length > 0) Set(_value.Substring(0, _value.Length - 1)); e.Handled = true; }
            base.OnKeyPress(e);
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            if (e.Control && e.KeyCode == Keys.V)
            {
                try
                {
                    var text = Clipboard.GetText();
                    var digits = "";
                    foreach (var c in text) if (char.IsDigit(c)) digits += c;
                    if (digits.Length > 0) Set((_value + digits).Substring(0, Math.Min(_maxLength, _value.Length + digits.Length)));
                }
                catch { }
                e.Handled = true;
            }
            base.OnKeyDown(e);
        }

        protected override void OnMouseDown(MouseEventArgs e) { Focus(); base.OnMouseDown(e); }
        protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
        protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Parent?.BackColor ?? SystemColors.Control);
            int box = Box, gap = Gap, h = Height - 2;
            var accent = Color.FromArgb(37, 99, 235);
            for (int i = 0; i < _slots; i++)
            {
                var r = new Rectangle(1 + i * (box + gap), 1, box, h);
                bool current = Focused && Enabled && (i == _value.Length || (i == _slots - 1 && _value.Length == _slots));
                using (var path = Rounded(r, Math.Max(4, box / 6)))
                {
                    using (var fill = new SolidBrush(Enabled ? SystemColors.Window : SystemColors.ControlLight)) g.FillPath(fill, path);
                    using (var pen = new Pen(current ? accent : (i < _value.Length ? Color.FromArgb(100, 116, 139) : Color.FromArgb(180, 188, 200)), current ? 2.5f : 1.5f))
                        g.DrawPath(pen, path);
                }
                if (i < _value.Length)
                {
                    int d = box / 3;
                    using (var dot = new SolidBrush(Color.FromArgb(30, 41, 59)))
                        g.FillEllipse(dot, r.X + (r.Width - d) / 2, r.Y + (r.Height - d) / 2, d, d);
                }
            }
        }

        private static GraphicsPath Rounded(Rectangle r, int radius)
        {
            int d = radius * 2;
            var p = new GraphicsPath();
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }
    }
}
