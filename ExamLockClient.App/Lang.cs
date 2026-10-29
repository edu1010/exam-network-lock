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
        ["incBlockedProc"] = new[] { "Prohibited program: {0}", "Programa prohibit: {0}", "Programa prohibido: {0}" },
        ["statusBlockedProc"] = new[] { "Prohibited program detected: {0}", "Programa prohibit detectat: {0}", "Programa prohibido detectado: {0}" },
        ["title"] = new[] { "Exam shield", "Escut d'examen", "Escudo de examen" },
        ["config"] = new[] { "Config", "Config", "Config" },
        ["radios"] = new[] { "Radios", "Ràdios", "Radios" },
        ["incidents"] = new[] { "Incidents", "Incidències", "Incidencias" },
        ["pwdA"] = new[] { "Re-enable Wi-Fi password", "Contrasenya per rehabilitar Wi-Fi", "Contraseña para rehabilitar Wi-Fi" },
        ["pwdB"] = new[] { "Close program password", "Contrasenya per tancar el programa", "Contraseña para cerrar el programa" },
        ["restoreBtn"] = new[] { "Re-enable Wi-Fi", "Rehabilitar Wi-Fi", "Rehabilitar Wi-Fi" },
        ["closeBtn"] = new[] { "Close program", "Tancar programa", "Cerrar programa" },
        ["loadBtn"] = new[] { "Load config…", "Carregar config…", "Cargar config…" },
        ["lockRadiosAdminBtn"] = new[] { "Lock radios (admin)", "Bloquejar ràdios (admin)", "Bloquear radios (admin)" },
        ["radiosLockedAdmin"] = new[] { "Radios locked with administrator permission.", "Ràdios bloquejades amb permís d'administrador.", "Radios bloqueadas con permiso de administrador." },
        ["statusRadioNeedsAdmin"] = new[] { "Radio lockdown failed without admin rights. The teacher can press 'Lock radios (admin)'.", "El bloqueig de ràdios ha fallat sense permisos. El professorat pot prémer 'Bloquejar ràdios (admin)'.", "El bloqueo de radios ha fallado sin permisos. El profesorado puede pulsar 'Bloquear radios (admin)'." },
        ["incRadioNeedsAdmin"] = new[] { "Radio lockdown needs administrator permission.", "El bloqueig de ràdios necessita permís d'administrador.", "El bloqueo de radios necesita permiso de administrador." },
        ["radiosAdminFailed"] = new[] { "Radios not locked: authorization canceled or failed ({0}).", "Ràdios no bloquejades: autorització cancel·lada o fallida ({0}).", "Radios no bloqueadas: autorización cancelada o fallida ({0})." },
        ["reopenAdminBtn"] = new[] { "Reopen as admin", "Reobrir com a admin", "Reabrir como admin" },
        ["defaultBtn"] = new[] { "Set default config…", "Config per defecte…", "Config por defecto…" },
        ["defaultTag"] = new[] { "[default]", "[per defecte]", "[por defecto]" },
        ["dlgSelectDefault"] = new[] { "Select the default config", "Selecciona la config per defecte", "Selecciona la config por defecto" },
        ["defaultSaved"] = new[] { "Default config saved: it loads every time the app opens.", "Config per defecte desada: es carrega cada cop que s'obre l'aplicació.", "Config por defecto guardada: se carga cada vez que se abre la aplicación." },
        ["defaultNeedsB"] = new[] { "To replace the default config, type its password B in the close box first.", "Per substituir la config per defecte, escriu primer la seva contrasenya B a la casella de tancar.", "Para sustituir la config por defecto, escribe primero su contraseña B en la casilla de cerrar." },
        ["defaultNotMarked"] = new[] { "That is an exam config. Open it with «Load config…»; a default config is generated with «Default config» ticked.", "Aquesta és una config d'examen. Obre-la amb «Carregar config…»; una config per defecte es genera amb «Config per defecte» marcat.", "Esa es una config de examen. Ábrela con «Cargar config…»; una config por defecto se genera con «Config por defecto» marcado." },
        ["defaultSaveFail"] = new[] { "Could not save the default config: {0}", "No s'ha pogut desar la config per defecte: {0}", "No se pudo guardar la config por defecto: {0}" },
        ["defaultPushed"] = new[] { "Default config updated from the teacher monitor.", "Config per defecte actualitzada des del monitor del professor.", "Config por defecto actualizada desde el monitor del profesor." },
        ["defaultPushedLater"] = new[] { "Default config updated from the teacher monitor (applies after this exam).", "Config per defecte actualitzada des del monitor (s'aplicarà després d'aquest examen).", "Config por defecto actualizada desde el monitor (se aplicará después de este examen)." },
        ["examPushed"] = new[] { "Exam config received from the teacher monitor.", "Config d'examen rebuda del monitor del professor.", "Config de examen recibida del monitor del profesor." },
        ["statusDefaultActive"] = new[] { "Default config active. Open the exam config with «Load config…».", "Config per defecte activa. Obre la config de l'examen amb «Carregar config…».", "Config por defecto activa. Abre la config del examen con «Cargar config…»." },
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
        ["wrongA"] = new[] { "Wrong re-enable Wi-Fi password.", "Contrasenya per rehabilitar Wi-Fi incorrecta.", "Contraseña para rehabilitar Wi-Fi incorrecta." },
        ["wrongB"] = new[] { "Wrong close program password.", "Contrasenya per tancar el programa incorrecta.", "Contraseña para cerrar el programa incorrecta." },
        ["wifiRestored"] = new[] { "Wi-Fi restored. The shield is still active.", "Wi-Fi restaurat. L'escut continua actiu.", "Wi-Fi restaurado. El escudo sigue activo." },
        ["submissionMode"] = new[] { "Internet restored for submission — folder checks paused.", "Internet restaurat per a l'entrega — comprovació de carpetes en pausa.", "Internet restaurado para la entrega — comprobación de carpetas en pausa." },
        ["needBToExit"] = new[] { "Enter the close program password to exit.", "Introdueix la contrasenya per tancar el programa per sortir.", "Introduce la contraseña para cerrar el programa para salir." },

        ["lockStarted"] = new[] { "Lockdown started.", "Bloqueig iniciat.", "Bloqueo iniciado." },
        ["incNoAdmin"] = new[] { "Running without elevated permissions.", "Executant-se sense permisos elevats.", "Ejecutando sin permisos elevados." },
        ["incAi"] = new[] { "⚠ AI detected: {0}", "⚠ IA detectada: {0}", "⚠ IA detectada: {0}" },
        ["incAiUrl"] = new[] { "⚠ AI website visited: {0}", "⚠ Web d'IA visitada: {0}", "⚠ Web de IA visitada: {0}" },
        ["statusAiUrl"] = new[] { "An AI website was opened in the browser. Notify the teacher.", "S'ha obert una web d'IA al navegador. Avisa el professor.", "Se ha abierto una web de IA en el navegador. Avisa al profesor." },
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
