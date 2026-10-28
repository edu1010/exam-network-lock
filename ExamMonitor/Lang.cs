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
        ["listeningOn"] = new[] { "Listening on {0} (UDP {1}). Put this IP in the config's teacher monitor IPs if students are on another network (e.g. Wi-Fi).", "Escoltant a {0} (UDP {1}). Posa aquesta IP a les IPs del monitor de la config si l'alumnat és en una altra xarxa (p. ex. Wi-Fi).", "Escuchando en {0} (UDP {1}). Pon esta IP en «IPs del monitor» de la config si el alumnado está en otra red (p. ej. Wi-Fi)." },
        ["savedTo"] = new[] { "Logs saved to: {0}", "Registres desats a: {0}", "Registros guardados en: {0}" },

        ["pushBtn"] = new[] { "Send default config…", "Enviar config per defecte…", "Enviar config por defecto…" },
        ["pushTip"] = new[] { "Install a config as the default config on every student shown as connected. Students running on their default config switch to it at once; an exam in progress is not interrupted.", "Instal·la una config com a config per defecte a tot l'alumnat connectat. Qui funcioni amb la config per defecte hi canvia a l'instant; un examen en curs no s'interromp.", "Instala una config como config por defecto en todo el alumnado conectado. Quien funcione con la config por defecto cambia al instante; un examen en curso no se interrumpe." },
        ["pushPrompt"] = new[] { "Password B (close) of the default config the {0} connected students currently have. If they have none yet, password B of the config they are running.", "Contrasenya B (tancar) de la config per defecte que tenen ara els {0} alumnes connectats. Si encara no en tenen, la contrasenya B de la config que executen.", "Contraseña B (cerrar) de la config por defecto que tienen ahora los {0} alumnos conectados. Si aún no tienen, la contraseña B de la config que están ejecutando." },
        ["pushExamBtn"] = new[] { "Send exam config…", "Enviar config d'examen…", "Enviar config de examen…" },
        ["pushExamTip"] = new[] { "Start an exam on every connected student running the default config. It is not kept as the default: the next time the app opens it goes back to the default config.", "Inicia un examen a tot l'alumnat connectat que funcioni amb la config per defecte. No es desa com a per defecte: el proper cop que s'obri l'aplicació torna a la config per defecte.", "Inicia un examen en todo el alumnado conectado que funcione con la config por defecto. No se guarda como por defecto: la próxima vez que se abra la aplicación vuelve a la config por defecto." },
        ["pushExamPrompt"] = new[] { "Password B (close) of the default config of the {0} students running it.", "Contrasenya B (tancar) de la config per defecte dels {0} alumnes que l'executen.", "Contraseña B (cerrar) de la config por defecto de los {0} alumnos que la están ejecutando." },
        ["pushExamDone"] = new[] { "Exam started on {0} of {1} students.", "Examen iniciat a {0} de {1} alumnes.", "Examen iniciado en {0} de {1} alumnos." },
        ["pushExamNoClients"] = new[] { "No connected students are running the default config.", "No hi ha alumnes connectats amb la config per defecte.", "No hay alumnos conectados con la config por defecto." },
        ["pushErrBusy"] = new[] { "already running an exam", "ja té un examen en curs", "ya tiene un examen en curso" },
        ["pushNotDefault"] = new[] { "This is an exam config, not a default one. Use «Send exam config…», or generate it with «Default config» ticked.", "Aquesta és una config d'examen, no per defecte. Fes servir «Enviar config d'examen…» o genera-la amb «Config per defecte» marcat.", "Esta es una config de examen, no por defecto. Usa «Enviar config de examen…» o genérala con «Config por defecto» marcado." },
        ["pushIsDefault"] = new[] { "This is a default config, not an exam. Use «Send default config…».", "Aquesta és una config per defecte, no un examen. Fes servir «Enviar config per defecte…».", "Esta es una config por defecto, no un examen. Usa «Enviar config por defecto…»." },
        ["pushErrKind"] = new[] { "wrong config type", "tipus de config incorrecte", "tipo de config incorrecto" },
        ["pushSend"] = new[] { "Send", "Enviar", "Enviar" },
        ["cancel"] = new[] { "Cancel", "Cancel·la", "Cancelar" },
        ["pushing"] = new[] { "Sending the config to {0} students…", "Enviant la config a {0} alumnes…", "Enviando la config a {0} alumnos…" },
        ["pushDone"] = new[] { "Default config updated on {0} of {1} students.", "Config per defecte actualitzada a {0} de {1} alumnes.", "Config por defecto actualizada en {0} de {1} alumnos." },
        ["pushNoClients"] = new[] { "No connected students to send to.", "No hi ha alumnes connectats a qui enviar-la.", "No hay alumnos conectados a los que enviarla." },
        ["pushErrAuth"] = new[] { "wrong password", "contrasenya incorrecta", "contraseña incorrecta" },
        ["pushErrNoConfig"] = new[] { "the client has no config loaded", "el client no té cap config carregada", "el cliente no tiene ninguna config cargada" },
        ["pushErrSave"] = new[] { "the client could not save the file", "el client no ha pogut desar el fitxer", "el cliente no pudo guardar el archivo" },
        ["pushErrUnreachable"] = new[] { "unreachable (old client version or firewall on TCP 48711?)", "inaccessible (versió antiga del client o tallafocs al TCP 48711?)", "inaccesible (¿versión antigua del cliente o cortafuegos en TCP 48711?)" },
        ["modeDefault"] = new[] { "default", "per defecte", "por defecto" },

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
