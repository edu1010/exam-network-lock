using System.Globalization;

namespace ExamLogVerifierUI;

public enum Language
{
    En,
    Ca,
    Es
}

/// <summary>UI string table (EN / CA / ES) with persisted, system-detected default. Shares the
/// suite's saved-language file so the chosen language follows the user across every tool.</summary>
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

    public static string T(string key) =>
        Table.TryGetValue(key, out var v) ? v[(int)Current] : key;

    private static readonly Dictionary<string, string[]> Table = new()
    {
        // key                         EN                                                  CA                                                  ES
        ["title"] = new[] { "Exam log verifier", "Verificador de registres d'examen", "Verificador de registros de examen" },

        ["btnLoadConfig"] = new[] { "Load config…", "Carrega config…", "Cargar config…" },
        ["btnAddLogs"] = new[] { "Add logs…", "Afegeix registres…", "Añadir logs…" },
        ["btnAddFolder"] = new[] { "Add folder…", "Afegeix carpeta…", "Añadir carpeta…" },
        ["btnVerify"] = new[] { "Verify", "Comprova", "Comprobar" },
        ["btnClear"] = new[] { "Clear", "Buida", "Limpiar" },
        ["btnExport"] = new[] { "Export summary…", "Exporta resum…", "Exportar resumen…" },

        ["configNone"] = new[] { "No config loaded — load exam.config to verify integrity.", "Cap config carregada — carrega exam.config per verificar la integritat.", "Sin config cargada — carga exam.config para verificar la integridad." },
        ["configLoaded"] = new[] { "Config: {0}  ✓ valid", "Config: {0}  ✓ vàlida", "Config: {0}  ✓ válida" },
        ["configInvalid"] = new[] { "Config: {0}  ✗ INVALID (tampered)", "Config: {0}  ✗ NO VÀLIDA (manipulada)", "Config: {0}  ✗ NO VÁLIDA (manipulada)" },
        ["configReadErr"] = new[] { "Could not read config: {0}", "No s'ha pogut llegir la config: {0}", "No se pudo leer la config: {0}" },

        ["leftFilter"] = new[] { "Show logs:", "Mostra registres:", "Mostrar logs:" },
        ["fAll"] = new[] { "All", "Tots", "Todos" },
        ["fTampered"] = new[] { "Tampered only", "Només manipulats", "Solo manipulados" },
        ["fIncidents"] = new[] { "With incidents", "Amb incidències", "Con incidencias" },
        ["fContains"] = new[] { "Contain: {0}", "Contenen: {0}", "Contienen: {0}" },

        ["rightFilter"] = new[] { "Events:", "Esdeveniments:", "Eventos:" },
        ["efAll"] = new[] { "All", "Tots", "Todos" },
        ["efIncidents"] = new[] { "Only incidents", "Només incidències", "Solo incidencias" },
        ["efCritical"] = new[] { "Only critical", "Només crítics", "Solo críticos" },
        ["efWarnings"] = new[] { "Only warnings", "Només avisos", "Solo avisos" },
        ["efInfo"] = new[] { "Only info", "Només informatius", "Solo informativos" },

        ["colStatus"] = new[] { "", "", "" },
        ["colName"] = new[] { "Folder / log", "Carpeta / registre", "Carpeta / log" },
        ["colSummary"] = new[] { "Result", "Resultat", "Resultado" },

        ["colLine"] = new[] { "#", "#", "#" },
        ["colTime"] = new[] { "Time", "Hora", "Hora" },
        ["colEvent"] = new[] { "Event", "Esdeveniment", "Evento" },
        ["colDetail"] = new[] { "Detail", "Detall", "Detalle" },
        ["colChain"] = new[] { "Chain", "Cadena", "Cadena" },

        ["chainCellOk"] = new[] { "ok", "ok", "ok" },
        ["chainCellBad"] = new[] { "ALTERED", "ALTERAT", "ALTERADO" },

        ["sumOk"] = new[] { "OK — intact, no incidents", "OK — íntegre, sense incidències", "OK — íntegro, sin incidencias" },
        ["sumTampered"] = new[] { "TAMPERED — chain broken at line {0}", "MANIPULAT — cadena trencada a la línia {0}", "MANIPULADO — cadena rota en la línea {0}" },
        ["sumUnverified"] = new[] { "Not verified (load config)", "Sense verificar (carrega config)", "Sin verificar (carga config)" },
        ["sumError"] = new[] { "Read error", "Error de lectura", "Error de lectura" },
        ["sumEmpty"] = new[] { "Empty log", "Registre buit", "Log vacío" },
        ["sumCrit"] = new[] { "{0} critical", "{0} crítics", "{0} críticas" },
        ["sumWarn"] = new[] { "{0} warnings", "{0} avisos", "{0} avisos" },

        ["dropHint"] = new[]
        {
            "Drag exam folders or examlog.jsonl files here",
            "Arrossega carpetes d'examen o fitxers examlog.jsonl aquí",
            "Arrastra aquí carpetas de examen o archivos examlog.jsonl"
        },
        ["selectHint"] = new[] { "Select a log on the left to see its events.", "Selecciona un registre a l'esquerra per veure'n els esdeveniments.", "Selecciona un log a la izquierda para ver sus eventos." },

        ["hdrSelected"] = new[] { "{0}  —  {1} events", "{0}  —  {1} esdeveniments", "{0}  —  {1} eventos" },
        ["chainIntact"] = new[] { "Chain intact", "Cadena íntegra", "Cadena íntegra" },
        ["chainBroken"] = new[] { "Chain altered (line {0})", "Cadena alterada (línia {0})", "Cadena alterada (línea {0})" },

        ["footer"] = new[]
        {
            "{0} logs · {1} OK · {2} with incidents · {3} tampered · {4} unverified",
            "{0} registres · {1} OK · {2} amb incidències · {3} manipulats · {4} sense verificar",
            "{0} logs · {1} OK · {2} con incidencias · {3} manipulados · {4} sin verificar"
        },

        ["footerCfgWarn"] = new[] { "   ·   ⚠ config not valid", "   ·   ⚠ config no vàlida", "   ·   ⚠ config no válida" },
        ["mismatchTitle"] = new[] { "Config may not match these logs", "La config pot no correspondre a aquests registres", "La config quizá no corresponde a estos logs" },
        ["mismatchMsg"] = new[]
        {
            "Every log fails from its first line. This usually means the loaded exam.config is from a different exam (its secret key does not match these logs), not that every student tampered with theirs. Load the exam.config that belongs to these logs.",
            "Tots els registres fallen des de la primera línia. Normalment vol dir que l'exam.config carregat és d'un altre examen (la seva clau secreta no coincideix amb aquests registres), no que tots els alumnes l'hagin manipulat. Carrega l'exam.config que correspon a aquests registres.",
            "Todos los logs fallan desde su primera línea. Normalmente significa que el exam.config cargado es de otro examen (su clave secreta no coincide con estos logs), no que todos los alumnos lo hayan manipulado. Carga el exam.config que corresponde a estos logs."
        },
        ["opErr"] = new[] { "Operation failed: {0}", "L'operació ha fallat: {0}", "La operación falló: {0}" },
        ["msgTitle"] = new[] { "Exam log verifier", "Verificador de registres", "Verificador de registros" },
        ["needConfig"] = new[] { "Load an exam.config first: its secret key is required to verify log integrity.", "Carrega primer un exam.config: cal la seva clau secreta per verificar la integritat.", "Carga primero un exam.config: su clave secreta es necesaria para verificar la integridad." },
        ["noLogsToVerify"] = new[] { "Add some logs first (drag folders or files in).", "Afegeix primer alguns registres (arrossega carpetes o fitxers).", "Añade primero algunos logs (arrastra carpetas o archivos)." },
        ["noLogsFound"] = new[] { "No examlog.jsonl files were found in what you dropped.", "No s'ha trobat cap examlog.jsonl en el que has deixat anar.", "No se encontró ningún examlog.jsonl en lo que soltaste." },

        ["dlgConfig"] = new[] { "Select exam.config", "Selecciona exam.config", "Selecciona exam.config" },
        ["dlgLogs"] = new[] { "Select log files (examlog.jsonl)", "Selecciona fitxers de registre (examlog.jsonl)", "Selecciona archivos de log (examlog.jsonl)" },
        ["dlgFolder"] = new[] { "Select a folder to scan for logs", "Selecciona una carpeta per cercar registres", "Selecciona una carpeta para buscar logs" },
        ["filterConfig"] = new[] { "Config files (*.config)|*.config|All files (*.*)|*.*", "Fitxers de config (*.config)|*.config|Tots (*.*)|*.*", "Archivos de config (*.config)|*.config|Todos (*.*)|*.*" },
        ["filterLogs"] = new[] { "Log files (*.jsonl)|*.jsonl|All files (*.*)|*.*", "Fitxers de registre (*.jsonl)|*.jsonl|Tots (*.*)|*.*", "Archivos de log (*.jsonl)|*.jsonl|Todos (*.*)|*.*" },

        ["exportTitle"] = new[] { "Export summary (CSV)", "Exporta resum (CSV)", "Exportar resumen (CSV)" },
        ["exportOk"] = new[] { "Summary exported to:\n{0}", "Resum exportat a:\n{0}", "Resumen exportado a:\n{0}" },
        ["exportErr"] = new[] { "Export failed: {0}", "Ha fallat l'exportació: {0}", "Falló la exportación: {0}" },
        ["csvHeader"] = new[] { "Folder,Path,Status,Critical,Warnings,FirstBrokenLine", "Carpeta,Ruta,Estat,Crítics,Avisos,PrimeraLiniaTrencada", "Carpeta,Ruta,Estado,Criticas,Avisos,PrimeraLineaRota" },

        // Localized event names (raw token shown if missing).
        ["ev.APP_STARTED"] = new[] { "App started", "Aplicació iniciada", "Aplicación iniciada" },
        ["ev.CONFIG_VALID"] = new[] { "Config validated", "Config validada", "Config validada" },
        ["ev.UNCLEAN_PREVIOUS_SESSION_DETECTED"] = new[] { "Previous session not closed cleanly", "Sessió anterior no tancada netament", "Sesión anterior no cerrada limpiamente" },
        ["ev.WIFI_DISABLED"] = new[] { "Wi-Fi disabled", "Wi-Fi desactivat", "Wi-Fi desactivado" },
        ["ev.WIFI_DISABLE_FAILED"] = new[] { "Wi-Fi disable failed", "Ha fallat desactivar Wi-Fi", "Falló desactivar Wi-Fi" },
        ["ev.WIFI_ENABLED"] = new[] { "Wi-Fi enabled", "Wi-Fi activat", "Wi-Fi activado" },
        ["ev.WIFI_ENABLE_FAILED"] = new[] { "Wi-Fi enable failed", "Ha fallat activar Wi-Fi", "Falló activar Wi-Fi" },
        ["ev.WIFI_RESTORED"] = new[] { "Wi-Fi restored", "Wi-Fi restaurat", "Wi-Fi restaurado" },
        ["ev.BT_DISABLED"] = new[] { "Bluetooth disabled", "Bluetooth desactivat", "Bluetooth desactivado" },
        ["ev.BT_ENABLED"] = new[] { "Bluetooth enabled", "Bluetooth activat", "Bluetooth activado" },
        ["ev.BT_FAILED"] = new[] { "Bluetooth operation failed", "Ha fallat l'operació de Bluetooth", "Falló la operación de Bluetooth" },
        ["ev.AI_DETECTED"] = new[] { "AI connection detected", "Connexió a IA detectada", "Conexión a IA detectada" },
        ["ev.AI_DNS_DETECTED"] = new[] { "Possible AI hostname resolved (DNS)", "Possible nom d'amfitrió d'IA resolt (DNS)", "Posible host de IA resuelto (DNS)" },
        ["ev.AI_UNATTRIBUTED_DETECTED"] = new[] { "Possible AI connection (unattributed)", "Possible connexió a IA (sense atribució)", "Posible conexión a IA (sin atribución)" },
        ["ev.AI_TOOL_DETECTED"] = new[] { "AI tool/process detected", "Eina/procés d'IA detectat", "Herramienta/proceso de IA detectado" },
        ["ev.VM_DETECTED"] = new[] { "Virtual machine detected", "Màquina virtual detectada", "Máquina virtual detectada" },
        ["ev.AI_CLEARED"] = new[] { "AI alarm cleared", "Alarma d'IA reconeguda", "Alarma de IA reconocida" },
        ["ev.UNKNOWN_PROCESS"] = new[] { "Unknown program started", "Programa desconegut iniciat", "Programa desconocido iniciado" },
        ["ev.FORBIDDEN_FILE"] = new[] { "Forbidden file opened", "Fitxer prohibit obert", "Archivo prohibido abierto" },
        ["ev.UNKNOWN_FILE"] = new[] { "Unknown file type", "Tipus de fitxer desconegut", "Tipo de archivo desconocido" },
        ["ev.OUTSIDE_FOLDER"] = new[] { "Work outside the allowed folder", "Treball fora de la carpeta permesa", "Trabajo fuera de la carpeta permitida" },
        ["ev.SHIELD_GREEN"] = new[] { "Shield: green", "Escut: verd", "Escudo: verde" },
        ["ev.SHIELD_YELLOW"] = new[] { "Shield: yellow", "Escut: groc", "Escudo: amarillo" },
        ["ev.SHIELD_RED"] = new[] { "Shield: red", "Escut: vermell", "Escudo: rojo" },
        ["ev.UNLOCK_SUCCESS"] = new[] { "Unlock succeeded", "Desbloqueig correcte", "Desbloqueo correcto" },
        ["ev.UNLOCK_FAILED"] = new[] { "Unlock attempt failed", "Intent de desbloqueig fallit", "Intento de desbloqueo fallido" },
        ["ev.ADMIN_CLOSE"] = new[] { "Admin close", "Tancament admin", "Cierre admin" },
        ["ev.ADMIN_AUTH_FAILED"] = new[] { "Admin auth failed", "Autenticació admin fallida", "Autenticación admin fallida" },
        ["ev.NORMAL_EXIT"] = new[] { "Normal exit", "Sortida normal", "Salida normal" },
        ["ev.INVALID_JSON"] = new[] { "Corrupt / unreadable line", "Línia corrupta / il·legible", "Línea corrupta / ilegible" },
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
            // Best-effort.
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
