using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FileLocker
{
    /// <summary>
    /// Holds the user's key pair.
    ///
    /// * A 2048-bit RSA key pair is created at setup.
    /// * The PUBLIC key is stored in plain text, so locking never needs the PIN.
    /// * The PRIVATE key is stored twice, each copy encrypted: once with a key derived from the
    ///   PIN/password and once with a key derived from the recovery key. Unlocking needs one of them.
    /// </summary>
    internal sealed class Vault
    {
        public const int PinIterations = 200000;
        public const int RecoveryIterations = 20000;

        public static string Dir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FileLocker");
        public static string LocalDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FileLocker");
        private static string ConfigPath => Path.Combine(Dir, "vault.cfg");
        private static string SessionPath => Path.Combine(LocalDir, "session.bin");

        public string Kind = "pin"; // "pin" or "password"
        public int Iterations = PinIterations;
        public int PinLength; // 0 = unknown (set up with an older version)
        public byte[] Salt, PinWrap, RecSalt, RecWrap, PublicKey;

        public static bool IsSetUp => File.Exists(ConfigPath);

        public static Vault Load()
        {
            var d = new Dictionary<string, string>();
            foreach (var line in File.ReadAllLines(ConfigPath))
            {
                int eq = line.IndexOf('=');
                if (eq > 0) d[line.Substring(0, eq).Trim()] = line.Substring(eq + 1).Trim();
            }
            return new Vault
            {
                Kind = d["kind"],
                Iterations = int.Parse(d["iterations"]),
                Salt = Convert.FromBase64String(d["salt"]),
                PinWrap = Convert.FromBase64String(d["pinWrap"]),
                RecSalt = Convert.FromBase64String(d["recSalt"]),
                RecWrap = Convert.FromBase64String(d["recWrap"]),
                PublicKey = Convert.FromBase64String(d["publicKey"]),
                PinLength = d.TryGetValue("pinLength", out var pl) && int.TryParse(pl, out var n) ? n : 0,
            };
        }

        private void Save()
        {
            Directory.CreateDirectory(Dir);
            var sb = new StringBuilder();
            sb.AppendLine("# FileLocker key file. Do not edit. Back it up together with your recovery key.");
            sb.AppendLine("version=1");
            sb.AppendLine("kind=" + Kind);
            sb.AppendLine("iterations=" + Iterations);
            sb.AppendLine("salt=" + Convert.ToBase64String(Salt));
            sb.AppendLine("pinWrap=" + Convert.ToBase64String(PinWrap));
            sb.AppendLine("recSalt=" + Convert.ToBase64String(RecSalt));
            sb.AppendLine("recWrap=" + Convert.ToBase64String(RecWrap));
            sb.AppendLine("publicKey=" + Convert.ToBase64String(PublicKey));
            if (PinLength > 0) sb.AppendLine("pinLength=" + PinLength);
            var tmp = ConfigPath + ".tmp";
            File.WriteAllText(tmp, sb.ToString());
            if (File.Exists(ConfigPath)) File.Replace(tmp, ConfigPath, null);
            else File.Move(tmp, ConfigPath);
        }

        /// <summary>First-time setup. Returns the recovery key the user must write down.</summary>
        public static string Create(string kind, string secret)
        {
            byte[] priv, pub;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                priv = rsa.ExportCspBlob(true);
                pub = rsa.ExportCspBlob(false);
            }
            var recovery = Crypto.NewRecoveryKey();
            var v = new Vault { PublicKey = pub, RecSalt = Crypto.Random(16) };
            v.RecWrap = Crypto.Wrap(Crypto.Derive(Crypto.NormalizeRecoveryKey(recovery), v.RecSalt, RecoveryIterations), priv);
            v.SetSecret(priv, kind, secret);
            return recovery;
        }

        /// <summary>Set (or change) the PIN/password protecting the private key.</summary>
        public void SetSecret(byte[] privateKey, string kind, string secret)
        {
            Kind = kind;
            PinLength = kind == "pin" ? secret.Length : 0;
            Iterations = PinIterations;
            Salt = Crypto.Random(16);
            PinWrap = Crypto.Wrap(Crypto.Derive(secret, Salt, Iterations), privateKey);
            Save();
            SessionClear();
        }

        /// <summary>Returns the private key if the PIN/password is right, otherwise null.</summary>
        /// <summary>Older setups didn't store the PIN length; it's saved after the first correct entry.</summary>
        public void RememberPinLength(int n) { PinLength = n; Save(); }

        public byte[] TryUnlock(string secret) => Crypto.Unwrap(Crypto.Derive(secret, Salt, Iterations), PinWrap);

        public byte[] TryRecover(string recoveryKey) =>
            Crypto.Unwrap(Crypto.Derive(Crypto.NormalizeRecoveryKey(recoveryKey), RecSalt, RecoveryIterations), RecWrap);

        public static string ValidateSecret(string kind, string secret)
        {
            if (kind == "pin")
            {
                if (secret.Length != 6) return "The PIN must be exactly 6 digits.";
                foreach (var c in secret) if (c < '0' || c > '9') return "A PIN can only contain digits.";
            }
            else if (secret.Length < 8) return "The password must have at least 8 characters.";
            return null;
        }

        // Version 0.2.0 and earlier remembered the PIN for 5 minutes in this file. That let a
        // double-click open a locked file without the PIN, so it was removed. The file is still
        // deleted wherever it might be left over.
        public static void SessionClear()
        {
            try { if (File.Exists(SessionPath)) File.Delete(SessionPath); } catch { }
        }
    }
}
