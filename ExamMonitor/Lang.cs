using System.Globalization;

namespace ExamMonitor;

public enum Language
{
    En,
    Ca,
    Es
}

/// <summary>UI string table (EN / CA / ES) with persisted, system-detected default.</summary>
internal static class Lang
{
    public static Language Current { get; private set; } = DetectDefault();

    public static void Set(Language language)
    {
        if (language == Current)
        {
            return;
        }

        Current = language;
        Save();
    }

    public static string T(string key) => Table.TryGetValue(key, out var v) ? v[(int)Current] : key;

    private static readonly Dictionary<string, string[]> Table = new()
    {
        ["title"] = new[] { "Exam monitor", "Monitor d'examen", "Monitor de examen" },
        ["loadBtn"] = new[] { "Load exam.config", "Carregar exam.config", "Cargar exam.config" },
        ["saveBtn"] = new[] { "Save logs", "Desar registres", "Guardar registros" },
        ["listening"] = new[] { "Listening on the LAN…", "Escoltant a la xarxa…", "Escuchando en la red…" },
        ["noConfig"] = new[] { "No exam.config: logs shown but integrity not verified.", "Sense exam.config: registres mostrats sense verificar la integritat.", "Sin exam.config: registros mostrados sin verificar la integridad." },
        ["configLoaded"] = new[] { "exam.config loaded: log integrity is verified.", "exam.config carregat: la integritat del registre es verifica.", "exam.config cargado: la integridad del registro se verifica." },
        ["configInvalid"] = new[] { "Invalid exam.config.", "exam.config no vàlid.", "exam.config no válido." },
        ["savedTo"] = new[] { "Logs saved to: {0}", "Registres desats a: {0}", "Registros guardados en: {0}" },

        ["colStudent"] = new[] { "Student", "Alumne", "Alumno" },
        ["colState"] = new[] { "State", "Estat", "Estado" },
        ["colIncident"] = new[] { "Last event", "Últim esdeveniment", "Último evento" },
        ["colEvents"] = new[] { "Events", "Esdeveniments", "Eventos" },
        ["colIntegrity"] = new[] { "Integrity", "Integritat", "Integridad" },
        ["colSeen"] = new[] { "Seen", "Vist", "Visto" },

        ["stIdle"] = new[] { "—", "—", "—" },
        ["stGreen"] = new[] { "OK", "OK", "OK" },
        ["stYellow"] = new[] { "ATTENTION", "ATENCIÓ", "ATENCIÓN" },
        ["stRed"] = new[] { "DANGER", "PERILL", "PELIGRO" },

        ["intOk"] = new[] { "OK", "OK", "OK" },
        ["intFail"] = new[] { "TAMPERED", "MANIPULAT", "MANIPULADO" },
        ["intPartial"] = new[] { "incomplete", "incomplet", "incompleto" },
        ["intNoKey"] = new[] { "no key", "sense clau", "sin clave" },
        ["secondsAgo"] = new[] { "{0}s ago", "fa {0}s", "hace {0}s" },
    };

    private static Language DetectDefault()
    {
        var saved = Load();
        if (saved.HasValue)
        {
            return saved.Value;
        }

        return CultureInfo.CurrentUICulture.TwoLetterISOLanguageName switch
        {
            "ca" => Language.Ca,
            "es" => Language.Es,
            _ => Language.En
        };
    }

    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ExamLock", "lang.txt");

    private static void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, Current.ToString());
        }
        catch
        {
        }
    }

    private static Language? Load()
    {
        try
        {
            if (File.Exists(FilePath) && Enum.TryParse<Language>(File.ReadAllText(FilePath).Trim(), out var l))
            {
                return l;
            }
        }
        catch
        {
        }

        return null;
    }
}
