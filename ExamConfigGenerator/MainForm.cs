using System.Security.Cryptography;
using System.Text;
using ExamShared;

namespace ExamConfigGenerator;

public sealed class MainForm : Form
{
    private readonly TextBox _passwordBox;
    private readonly TextBox _confirmBox;
    private readonly Button _generateButton;
    private readonly Label _statusLabel;

    public MainForm()
    {
        Text = "Exam Config Generator";
        Width = 520;
        Height = 240;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(12),
            ColumnCount = 2,
            RowCount = 4
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 35));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 65));

        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        layout.Controls.Add(new Label { Text = "Unlock Password", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 0);
        layout.Controls.Add(new Label { Text = "Confirm Password", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 1);

        _passwordBox = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Fill };
        _confirmBox = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Fill };

        layout.Controls.Add(_passwordBox, 1, 0);
        layout.Controls.Add(_confirmBox, 1, 1);

        _generateButton = new Button { Text = "Generate Config", Dock = DockStyle.Fill };
        _generateButton.Click += (_, _) => GenerateConfig();
        layout.Controls.Add(_generateButton, 1, 2);

        _statusLabel = new Label { Text = "", Dock = DockStyle.Fill, AutoSize = false, TextAlign = ContentAlignment.TopLeft };
        layout.SetColumnSpan(_statusLabel, 2);
        layout.Controls.Add(_statusLabel, 0, 3);

        Controls.Add(layout);
    }

    private void GenerateConfig()
    {
        var password = _passwordBox.Text;
        var confirm = _confirmBox.Text;

        if (string.IsNullOrWhiteSpace(password))
        {
            SetStatus("Password cannot be empty.");
            return;
        }

        if (!string.Equals(password, confirm, StringComparison.Ordinal))
        {
            SetStatus("Passwords do not match.");
            return;
        }

        var saveDialog = new SaveFileDialog
        {
            Title = "Save exam.config",
            Filter = "Config Files (*.config)|*.config|All Files (*.*)|*.*",
            FileName = "exam.config"
        };

        if (saveDialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        try
        {
            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);
            var iterations = 150_000;
            var hashBase64 = PasswordHasher.HashPassword(password, salt, iterations, 32);

            var logSecret = new byte[32];
            RandomNumberGenerator.Fill(logSecret);

            var payload = new ConfigPayload
            {
                Version = 1,
                SaltBase64 = Convert.ToBase64String(salt),
                Iterations = iterations,
                PasswordHashBase64 = hashBase64,
                LogSecretBase64 = Convert.ToBase64String(logSecret)
            };

            var payloadJson = ConfigSerializer.SerializePayload(payload);
            var hmac = ConfigIntegrityService.ComputeHmacBase64(payloadJson);

            var envelope = new ConfigEnvelope
            {
                Payload = payload,
                HmacBase64 = hmac
            };

            var configJson = ConfigSerializer.SerializeEnvelope(envelope);
            File.WriteAllText(saveDialog.FileName, configJson, Encoding.UTF8);

            SetStatus($"Config generated: {saveDialog.FileName}");
        }
        catch (Exception ex)
        {
            SetStatus($"Failed to generate config: {ex.Message}");
        }
    }

    private void SetStatus(string message)
    {
        _statusLabel.Text = message;
    }
}
