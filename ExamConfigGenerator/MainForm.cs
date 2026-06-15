using System.Security.Cryptography;
using System.Text;
using ExamShared;

namespace ExamConfigGenerator;

public sealed class MainForm : Form
{
    private const int SectionWidth = 600;

    private readonly TextBox _passwordBox;
    private readonly TextBox _confirmBox;
    private readonly TextBox _adminPasswordBox;
    private readonly TextBox _adminConfirmBox;

    private readonly CheckBox _disableWifiCheck;
    private readonly CheckBox _disableBluetoothCheck;
    private readonly CheckBox _aiShieldCheck;
    private readonly CheckBox _raiseVolumeCheck;

    private readonly ListBox _aiList;
    private readonly TextBox _aiInput;
    private readonly ListBox _appList;
    private readonly TextBox _extensionsBox;
    private readonly CheckBox _restrictFolderCheck;
    private readonly ComboBox _workFolderModeCombo;
    private readonly TextBox _workFolderBox;
    private readonly Label _workFolderHint;

    private readonly Button _generateButton;
    private readonly Label _statusLabel;

    public MainForm()
    {
        Text = "Generador de configuración de examen";
        Width = 680;
        Height = 820;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(640, 600);
        BackColor = Theme.Background;
        Font = Theme.Base;
        ForeColor = Theme.Text;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(16),
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Theme.Background
        };
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));

        var content = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true,
            BackColor = Theme.Background
        };

        // --- Passwords ---
        var pwdSection = Theme.Section("Contraseñas");
        var pwdGrid = SectionGrid(4);
        _passwordBox = AddPasswordRow(pwdGrid, 0, "Contraseña A — Restaurar Wi-Fi");
        _confirmBox = AddPasswordRow(pwdGrid, 1, "Confirmar contraseña A");
        _adminPasswordBox = AddPasswordRow(pwdGrid, 2, "Contraseña B — Cerrar / Admin");
        _adminConfirmBox = AddPasswordRow(pwdGrid, 3, "Confirmar contraseña B");
        pwdSection.Controls.Add(pwdGrid);
        content.Controls.Add(pwdSection);

        // --- Radios ---
        var radioSection = Theme.Section("Radios");
        var radioStack = VerticalStack();
        _disableWifiCheck = AddCheck(radioStack, "Desactivar Wi-Fi al iniciar (best-effort)", true);
        _disableBluetoothCheck = AddCheck(radioStack, "Desactivar Bluetooth al iniciar", false);
        radioSection.Controls.Add(radioStack);
        content.Controls.Add(radioSection);

        // --- AI shield ---
        var aiSection = Theme.Section("Escudo anti-IA");
        var aiStack = VerticalStack();
        _aiShieldCheck = AddCheck(aiStack, "Activar escudo anti-IA (vigila conexiones a IA)", true);
        _raiseVolumeCheck = AddCheck(aiStack, "Subir volumen y pitar al detectar IA", true);
        aiStack.Controls.Add(new Label { Text = "Dominios/IPs considerados IA:", AutoSize = true, ForeColor = Theme.TextMuted, Margin = new Padding(0, 8, 0, 2) });
        _aiList = new ListBox { Width = SectionWidth - 30, Height = 120, Margin = new Padding(0, 0, 0, 6) };
        Theme.StyleList(_aiList);
        foreach (var d in ConfigDefaults.DefaultAiBlocklist)
        {
            _aiList.Items.Add(d);
        }

        aiStack.Controls.Add(_aiList);
        _aiInput = new TextBox { Width = 360 };
        Theme.StyleInput(_aiInput);
        aiStack.Controls.Add(InputWithButtons(_aiInput,
            ("Añadir", () => AddToList(_aiList, _aiInput)),
            ("Quitar", () => RemoveSelected(_aiList))));
        aiSection.Controls.Add(aiStack);
        content.Controls.Add(aiSection);

        // --- Allowed apps ---
        var appSection = Theme.Section("Programas permitidos");
        var appStack = VerticalStack();
        appStack.Controls.Add(new Label { Text = "Ejecutables permitidos (ej. eclipse.exe). Vacío = sin restricción.", AutoSize = true, ForeColor = Theme.TextMuted, Margin = new Padding(0, 0, 0, 2) });
        _appList = new ListBox { Width = SectionWidth - 30, Height = 100, Margin = new Padding(0, 0, 0, 6) };
        Theme.StyleList(_appList);
        appStack.Controls.Add(_appList);
        var appManual = new TextBox { Width = 260 };
        Theme.StyleInput(appManual);
        appStack.Controls.Add(InputWithButtons(appManual,
            ("Añadir .exe…", BrowseExe),
            ("Añadir", () => AddToList(_appList, appManual)),
            ("Quitar", () => RemoveSelected(_appList))));
        appSection.Controls.Add(appStack);
        content.Controls.Add(appSection);

        // --- Files & folder ---
        var fileSection = Theme.Section("Archivos y carpeta de trabajo");
        var fileStack = VerticalStack();
        fileStack.Controls.Add(new Label { Text = "Extensiones permitidas, separadas por comas (ej. .java,.txt,.pdf). Vacío = sin restricción.", AutoSize = true, ForeColor = Theme.TextMuted, Margin = new Padding(0, 0, 0, 2) });
        _extensionsBox = new TextBox { Width = SectionWidth - 30, Margin = new Padding(0, 0, 0, 10) };
        Theme.StyleInput(_extensionsBox);
        fileStack.Controls.Add(_extensionsBox);

        _restrictFolderCheck = AddCheck(fileStack, "Restringir el trabajo a una carpeta y sus subcarpetas", false);
        fileStack.Controls.Add(new Label { Text = "Base de la carpeta (se resuelve en el equipo del alumno):", AutoSize = true, ForeColor = Theme.TextMuted, Margin = new Padding(0, 6, 0, 2) });
        _workFolderModeCombo = new ComboBox
        {
            Width = SectionWidth - 30,
            DropDownStyle = ComboBoxStyle.DropDownList,
            FlatStyle = FlatStyle.Flat,
            Font = Theme.Base
        };
        _workFolderModeCombo.Items.AddRange(new object[]
        {
            "Donde esté exam.config (recomendado)",
            "Escritorio del alumno",
            "Documentos del alumno",
            "Ruta fija (igual en todos los equipos)"
        });
        _workFolderModeCombo.SelectedIndex = 0;
        _workFolderModeCombo.SelectedIndexChanged += (_, _) => UpdateWorkFolderHint();
        fileStack.Controls.Add(_workFolderModeCombo);

        fileStack.Controls.Add(new Label { Text = "Subcarpeta opcional (o ruta fija):", AutoSize = true, ForeColor = Theme.TextMuted, Margin = new Padding(0, 6, 0, 2) });
        _workFolderBox = new TextBox { Width = 440 };
        Theme.StyleInput(_workFolderBox);
        fileStack.Controls.Add(InputWithButtons(_workFolderBox, ("Examinar…", BrowseFolder)));

        _workFolderHint = new Label { Text = "", AutoSize = true, ForeColor = Theme.TextMuted, Margin = new Padding(0, 2, 0, 0) };
        fileStack.Controls.Add(_workFolderHint);
        UpdateWorkFolderHint();

        fileSection.Controls.Add(fileStack);
        content.Controls.Add(fileSection);

        root.Controls.Add(content, 0, 0);

        _generateButton = new Button { Text = "Generar configuración", Dock = DockStyle.Fill, Margin = new Padding(0, 6, 0, 6) };
        Theme.StylePrimary(_generateButton);
        _generateButton.Click += (_, _) => GenerateConfig();
        root.Controls.Add(_generateButton, 0, 1);

        _statusLabel = new Label { Text = "", Dock = DockStyle.Fill, AutoSize = false, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.TextMuted };
        root.Controls.Add(_statusLabel, 0, 2);

        Controls.Add(root);
    }

    // ----- UI builders -----

    private static TableLayoutPanel SectionGrid(int rows)
    {
        var grid = new TableLayoutPanel
        {
            ColumnCount = 2,
            RowCount = rows,
            Width = SectionWidth - 24,
            AutoSize = true,
            BackColor = Theme.Background
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 230));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        return grid;
    }

    private static FlowLayoutPanel VerticalStack()
    {
        return new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoSize = true,
            Width = SectionWidth - 24,
            BackColor = Theme.Background
        };
    }

    private TextBox AddPasswordRow(TableLayoutPanel grid, int row, string label)
    {
        grid.Controls.Add(new Label { Text = label, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.Text }, 0, row);
        var box = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Fill, Margin = new Padding(0, 4, 0, 4) };
        Theme.StyleInput(box);
        grid.Controls.Add(box, 1, row);
        return box;
    }

    private CheckBox AddCheck(Control parent, string label, bool isChecked)
    {
        var check = new CheckBox { Text = label, Checked = isChecked, AutoSize = true, ForeColor = Theme.Text, Margin = new Padding(0, 3, 0, 3) };
        parent.Controls.Add(check);
        return check;
    }

    private FlowLayoutPanel InputWithButtons(Control input, params (string text, Action action)[] buttons)
    {
        var row = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 8), BackColor = Theme.Background };
        row.Controls.Add(input);
        foreach (var (text, action) in buttons)
        {
            var button = new Button { Text = text, AutoSize = true, Margin = new Padding(6, 0, 0, 0), Padding = new Padding(8, 4, 8, 4) };
            Theme.StyleSecondary(button);
            button.Click += (_, _) => action();
            row.Controls.Add(button);
        }

        return row;
    }

    private static void AddToList(ListBox list, TextBox input)
    {
        var value = input.Text.Trim();
        if (value.Length == 0)
        {
            return;
        }

        if (!list.Items.Contains(value))
        {
            list.Items.Add(value);
        }

        input.Clear();
    }

    private static void RemoveSelected(ListBox list)
    {
        if (list.SelectedItem is not null)
        {
            list.Items.Remove(list.SelectedItem);
        }
    }

    private void BrowseExe()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Selecciona el ejecutable permitido",
            Filter = "Programas (*.exe)|*.exe|Todos los archivos (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            var name = Path.GetFileName(dialog.FileName);
            if (!_appList.Items.Contains(name))
            {
                _appList.Items.Add(name);
            }
        }
    }

    private void BrowseFolder()
    {
        using var dialog = new FolderBrowserDialog { Description = "Selecciona la carpeta de examen (ruta fija, igual en todos los equipos)" };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            _workFolderModeCombo.SelectedIndex = 3; // Ruta fija (Absolute)
            _workFolderBox.Text = dialog.SelectedPath;
            UpdateWorkFolderHint();
        }
    }

    private string SelectedWorkFolderMode() => _workFolderModeCombo.SelectedIndex switch
    {
        1 => WorkFolderModes.Desktop,
        2 => WorkFolderModes.Documents,
        3 => WorkFolderModes.Absolute,
        _ => WorkFolderModes.ConfigFolder
    };

    private void UpdateWorkFolderHint()
    {
        if (_workFolderHint is null)
        {
            return;
        }

        var sub = _workFolderBox?.Text?.Trim() ?? "";
        _workFolderHint.Text = SelectedWorkFolderMode() switch
        {
            WorkFolderModes.Desktop => "En cada equipo: Escritorio\\" + (sub.Length > 0 ? sub : "(toda la carpeta del Escritorio)"),
            WorkFolderModes.Documents => "En cada equipo: Documentos\\" + (sub.Length > 0 ? sub : "(toda la carpeta de Documentos)"),
            WorkFolderModes.Absolute => "Esa ruta exacta debe existir en todos los portátiles (no recomendado entre usuarios distintos).",
            _ => "El alumno coloca exam.config dentro de la carpeta del examen; se vigila esa carpeta y sus subcarpetas."
        };
    }

    private void Warn(string message)
    {
        SetStatus(message);
        MessageBox.Show(this, message, "Configuración de examen", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    // ----- Config generation -----

    private void GenerateConfig()
    {
        var password = _passwordBox.Text;
        var confirm = _confirmBox.Text;
        var adminPassword = _adminPasswordBox.Text;
        var adminConfirm = _adminConfirmBox.Text;

        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(adminPassword))
        {
            Warn("Las dos contraseñas son obligatorias.");
            return;
        }

        if (!string.Equals(password, confirm, StringComparison.Ordinal))
        {
            Warn("La contraseña A no coincide con su confirmación.");
            return;
        }

        if (!string.Equals(adminPassword, adminConfirm, StringComparison.Ordinal))
        {
            Warn("La contraseña B no coincide con su confirmación.");
            return;
        }

        if (string.Equals(password, adminPassword, StringComparison.Ordinal))
        {
            Warn("Las contraseñas A y B deben ser distintas.");
            return;
        }

        var workFolderMode = SelectedWorkFolderMode();
        var folderText = _workFolderBox.Text.Trim();
        var workFolderAbsolute = workFolderMode == WorkFolderModes.Absolute ? folderText : "";
        var workFolderRelative = workFolderMode == WorkFolderModes.Absolute ? "" : folderText;

        if (_restrictFolderCheck.Checked && workFolderMode == WorkFolderModes.Absolute && workFolderAbsolute.Length == 0)
        {
            Warn("Para 'Ruta fija' debes indicar la ruta de la carpeta.");
            return;
        }

        var saveDialog = new SaveFileDialog
        {
            Title = "Guardar exam.config",
            Filter = "Config Files (*.config)|*.config|All Files (*.*)|*.*",
            FileName = "exam.config"
        };

        if (saveDialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        try
        {
            const int iterations = 150_000;

            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);
            var hashBase64 = PasswordHasher.HashPassword(password, salt, iterations, 32);

            var adminSalt = new byte[16];
            RandomNumberGenerator.Fill(adminSalt);
            var adminHashBase64 = PasswordHasher.HashPassword(adminPassword, adminSalt, iterations, 32);

            var logSecret = new byte[32];
            RandomNumberGenerator.Fill(logSecret);

            var payload = new ConfigPayload
            {
                Version = 2,
                SaltBase64 = Convert.ToBase64String(salt),
                Iterations = iterations,
                PasswordHashBase64 = hashBase64,
                AdminSaltBase64 = Convert.ToBase64String(adminSalt),
                AdminPasswordHashBase64 = adminHashBase64,
                LogSecretBase64 = Convert.ToBase64String(logSecret),
                DisableWifi = _disableWifiCheck.Checked,
                DisableBluetooth = _disableBluetoothCheck.Checked,
                AiShieldEnabled = _aiShieldCheck.Checked,
                RaiseVolumeOnAi = _raiseVolumeCheck.Checked,
                BeepOnViolation = true,
                AiBlocklist = _aiList.Items.Cast<string>().ToArray(),
                AllowedProcesses = _appList.Items.Cast<string>().ToArray(),
                AllowedFileExtensions = ParseExtensions(_extensionsBox.Text),
                WorkFolderMode = workFolderMode,
                WorkFolderRelative = workFolderRelative,
                WorkFolder = workFolderAbsolute,
                RestrictToWorkFolder = _restrictFolderCheck.Checked
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

            SetStatus($"Configuración generada: {saveDialog.FileName}");
            MessageBox.Show(this, $"Configuración generada correctamente:\n{saveDialog.FileName}", "Configuración de examen", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            SetStatus($"Error al generar la configuración: {ex.Message}");
            MessageBox.Show(this, $"Error al generar la configuración:\n{ex.Message}", "Configuración de examen", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static string[] ParseExtensions(string raw)
    {
        return raw
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(e => e.StartsWith('.') ? e.ToLowerInvariant() : "." + e.ToLowerInvariant())
            .Distinct()
            .ToArray();
    }

    private void SetStatus(string message)
    {
        _statusLabel.Text = message;
    }
}
