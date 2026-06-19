using System.Globalization;

namespace ExamLockClient.App;

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
    public static event Action? Changed;

    public static void Set(Language language)
    {
        if (language == Current)
        {
            return;
        }

        Current = language;
        Save();
        Changed?.Invoke();
    }

    public static string T(string key) =>
        Table.TryGetValue(key, out var v) ? v[(int)Current] : key;

    private static readonly Dictionary<string, string[]> Table = new()
    {
        ["title"] = new[] { "Exam shield", "Escut d'examen", "Escudo de examen" },
        ["config"] = new[] { "Config", "Config", "Config" },
        ["radios"] = new[] { "Radios", "Ràdios", "Radios" },
        ["incidents"] = new[] { "Incidents", "Incidències", "Incidencias" },
        ["pwdA"] = new[] { "Restore Wi-Fi password", "Contrasenya per restaurar Wi-Fi", "Contraseña para restaurar Wi-Fi" },
        ["pwdB"] = new[] { "Close program password", "Contrasenya per tancar el programa", "Contraseña para cerrar el programa" },
        ["restoreBtn"] = new[] { "Restore Wi-Fi", "Restaurar Wi-Fi", "Restaurar Wi-Fi" },
        ["closeBtn"] = new[] { "Close program", "Tancar programa", "Cerrar programa" },
        ["loadBtn"] = new[] { "Load config…", "Carregar config…", "Cargar config…" },
        ["reopenAdminBtn"] = new[] { "Reopen as admin", "Reobrir com a admin", "Reabrir como admin" },
        ["notLoaded"] = new[] { "(not loaded)", "(no carregada)", "(no cargada)" },
        ["waitingConfig"] = new[] { "Waiting for configuration…", "Esperant configuració…", "Esperando configuración…" },
        ["shieldProtected"] = new[] { "PROTECTED", "PROTEGIT", "PROTEGIDO" },
        ["shieldAttention"] = new[] { "ATTENTION", "ATENCIÓ", "ATENCIÓN" },
        ["shieldDanger"] = new[] { "DANGER", "PERILL", "PELIGRO" },

        ["dlgSelectConfig"] = new[] { "Select exam.config", "Selecciona exam.config", "Selecciona exam.config" },
        ["adminTitle"] = new[] { "Administrator permissions", "Permisos d'administrador", "Permisos de administrador" },
        ["adminRelaunchFail"] = new[] { "Could not relaunch with elevated permissions. The app will continue without elevation.", "No s'ha pogut reobrir amb permisos elevats. L'app continuarà sense elevació.", "No se pudo reabrir con permisos elevados. La app continuará sin elevación." },
        ["adminRelaunchCanceled"] = new[] { "Elevated relaunch canceled.", "Reobertura amb permisos elevats cancel·lada.", "Reapertura con permisos elevados cancelada." },
        ["needConfig"] = new[] { "A configuration file is required to start.", "Cal un fitxer de configuració per començar.", "Se necesita un archivo de configuración para empezar." },
        ["integrityFail"] = new[] { "Configuration integrity is invalid.", "La integritat de la configuració no és vàlida.", "La integridad de la configuración no es válida." },
        ["loadFail"] = new[] { "Could not load configuration: {0}", "No s'ha pogut carregar la configuració: {0}", "No se pudo cargar la configuración: {0}" },
        ["needValidConfig"] = new[] { "Load a valid configuration first.", "Carrega una configuració vàlida primer.", "Carga una configuración válida primero." },

        ["statusActive"] = new[] { "Exam in progress. The shield is active.", "Examen en curs. L'escut està actiu.", "Examen en curso. El escudo está activo." },
        ["statusNoAdmin"] = new[] { "Running without elevated permissions. Radio lockdown may fail.", "S'executa sense permisos elevats. El bloqueig de ràdios pot fallar.", "Ejecutando sin permisos elevados. El bloqueo de radios puede fallar." },
        ["statusAi"] = new[] { "AI connection attributed to a browser, IDE, or developer tool. Notify the teacher.", "Connexió a IA atribuïda a un navegador, IDE o eina de desenvolupament. Avisa el professor.", "Conexión a IA atribuida a un navegador, IDE o herramienta de desarrollo. Avisa al profesor." },
        ["statusAiPossible"] = new[] { "Possible AI connection detected. Process not confirmed.", "Possible connexió a IA detectada. Procés no confirmat.", "Posible conexión a IA detectada. Proceso no confirmado." },
        ["statusForbidden"] = new[] { "A forbidden file was opened.", "S'ha obert un fitxer no permès.", "Se ha abierto un archivo no permitido." },
        ["statusOutside"] = new[] { "Working outside the exam folder.", "S'està treballant fora de la carpeta de l'examen.", "Se está trabajando fuera de la carpeta del examen." },
        ["statusUnknownProc"] = new[] { "Unauthorized program opened: {0}", "Programa no autoritzat obert: {0}", "Programa no autorizado abierto: {0}" },
        ["statusUnknownFile"] = new[] { "Unrecognized file type: {0}", "Tipus de fitxer no reconegut: {0}", "Archivo de tipo no reconocido: {0}" },
        ["wrongA"] = new[] { "Wrong restore Wi-Fi password.", "Contrasenya per restaurar Wi-Fi incorrecta.", "Contraseña para restaurar Wi-Fi incorrecta." },
        ["wrongB"] = new[] { "Wrong close program password.", "Contrasenya per tancar el programa incorrecta.", "Contraseña para cerrar el programa incorrecta." },
        ["wifiRestored"] = new[] { "Wi-Fi restored. The shield is still active.", "Wi-Fi restaurat. L'escut continua actiu.", "Wi-Fi restaurado. El escudo sigue activo." },
        ["submissionMode"] = new[] { "Internet restored for submission — folder checks paused.", "Internet restaurat per a l'entrega — comprovació de carpetes en pausa.", "Internet restaurado para la entrega — comprobación de carpetas en pausa." },
        ["needBToExit"] = new[] { "Enter the close program password to exit.", "Introdueix la contrasenya per tancar el programa per sortir.", "Introduce la contraseña para cerrar el programa para salir." },

        ["lockStarted"] = new[] { "Lockdown started.", "Bloqueig iniciat.", "Bloqueo iniciado." },
        ["incNoAdmin"] = new[] { "Running without elevated permissions.", "Executant-se sense permisos elevats.", "Ejecutando sin permisos elevados." },
        ["incAi"] = new[] { "⚠ AI detected: {0}", "⚠ IA detectada: {0}", "⚠ IA detectada: {0}" },
        ["incAiPossible"] = new[] { "Possible AI activity: {0}", "Possible activitat d'IA: {0}", "Posible actividad de IA: {0}" },
        ["incAiTool"] = new[] { "⚠ AI tool: {0}", "⚠ Eina d'IA: {0}", "⚠ Herramienta de IA: {0}" },
        ["incVm"] = new[] { "⛔ Virtual machine: {0}", "⛔ Màquina virtual: {0}", "⛔ Máquina virtual: {0}" },
        ["statusVm"] = new[] { "Virtual machine detected. Notify the teacher.", "Màquina virtual detectada. Avisa el professor.", "Máquina virtual detectada. Avisa al profesor." },
        ["incForbidden"] = new[] { "⛔ Forbidden file: {0}", "⛔ Fitxer no permès: {0}", "⛔ Archivo no permitido: {0}" },
        ["incOutside"] = new[] { "⛔ Outside the exam folder: {0}", "⛔ Fora de la carpeta de l'examen: {0}", "⛔ Fuera de la carpeta de examen: {0}" },
        ["incUnknownProc"] = new[] { "❔ Unknown program: {0}", "❔ Programa desconegut: {0}", "❔ Programa desconocido: {0}" },
        ["incUnknownFile"] = new[] { "❔ Unknown file: {0}", "❔ Fitxer desconegut: {0}", "❔ Archivo desconocido: {0}" },

        ["wifiOff"] = new[] { "Wi-Fi: off", "Wi-Fi: desactivat", "Wi-Fi: desactivado" },
        ["wifiOffFail"] = new[] { "Wi-Fi: disable failed", "Wi-Fi: error en desactivar", "Wi-Fi: fallo al desactivar" },
        ["wifiWatched"] = new[] { "Wi-Fi: on (watched)", "Wi-Fi: actiu (vigilat)", "Wi-Fi: activo (vigilado)" },
        ["wifiOn"] = new[] { "Wi-Fi: on", "Wi-Fi: actiu", "Wi-Fi: activo" },
        ["wifiOnFail"] = new[] { "Wi-Fi: enable failed", "Wi-Fi: error en activar", "Wi-Fi: fallo al activar" },
        ["btOff"] = new[] { "BT: off", "BT: desactivat", "BT: desactivado" },
        ["btOn"] = new[] { "BT: on", "BT: actiu", "BT: activo" },
        ["btFail"] = new[] { "BT: failed", "BT: error", "BT: fallo" },
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
            // Persistence is best-effort.
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
            // Ignore.
        }

        return null;
    }
}
