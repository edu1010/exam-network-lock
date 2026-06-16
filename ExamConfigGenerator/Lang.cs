using System.Globalization;

namespace ExamConfigGenerator;

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

    public static string T(string key) =>
        Table.TryGetValue(key, out var v) ? v[(int)Current] : key;

    private static readonly Dictionary<string, string[]> Table = new()
    {
        // key                EN                                              CA                                                  ES
        ["title"] = new[] { "Exam config generator", "Generador de configuració d'examen", "Generador de configuración de examen" },
        ["secPasswords"] = new[] { "Passwords", "Contrasenyes", "Contraseñas" },
        ["secRadios"] = new[] { "Radios", "Ràdios", "Radios" },
        ["secAi"] = new[] { "AI shield", "Escut anti-IA", "Escudo anti-IA" },
        ["secApps"] = new[] { "Allowed programs", "Programes permesos", "Programas permitidos" },
        ["secFiles"] = new[] { "Files and work folder", "Fitxers i carpeta de treball", "Archivos y carpeta de trabajo" },

        ["pwdA"] = new[] { "Password A — Restore Wi-Fi", "Contrasenya A — Restaurar Wi-Fi", "Contraseña A — Restaurar Wi-Fi" },
        ["pwdAc"] = new[] { "Confirm password A", "Confirmar contrasenya A", "Confirmar contraseña A" },
        ["pwdB"] = new[] { "Password B — Close / Admin", "Contrasenya B — Tancar / Admin", "Contraseña B — Cerrar / Admin" },
        ["pwdBc"] = new[] { "Confirm password B", "Confirmar contrasenya B", "Confirmar contraseña B" },

        ["chkWifi"] = new[] { "Disable Wi-Fi on start (best-effort)", "Desactivar Wi-Fi en iniciar (best-effort)", "Desactivar Wi-Fi al iniciar (best-effort)" },
        ["chkBt"] = new[] { "Disable Bluetooth on start", "Desactivar Bluetooth en iniciar", "Desactivar Bluetooth al iniciar" },
        ["chkAi"] = new[] { "Enable AI shield (monitor AI connections)", "Activar escut anti-IA (vigila connexions a IA)", "Activar escudo anti-IA (vigila conexiones a IA)" },
        ["chkVol"] = new[] { "Raise volume and beep on AI detection", "Apujar volum i xiular en detectar IA", "Subir volumen y pitar al detectar IA" },
        ["chkVm"] = new[] { "Detect virtual machines (VirtualBox, VMware, Hyper-V…)", "Detectar màquines virtuals (VirtualBox, VMware, Hyper-V…)", "Detectar máquinas virtuales (VirtualBox, VMware, Hyper-V…)" },
        ["beepModeLabel"] = new[] { "Alarm sound:", "So de l'alarma:", "Sonido de la alarma:" },
        ["beepContinuous"] = new[] { "Continuous tone (until acknowledged)", "To continu (fins a reconèixer)", "Tono continuo (hasta reconocer)" },
        ["beepThree"] = new[] { "Three beeps per incident", "Tres xiulets per incidència", "Tres pitidos por incidencia" },
        ["volumeLabel"] = new[] { "Alarm volume level:", "Nivell de volum de l'alarma:", "Nivel de volumen de la alarma:" },
        ["aiListLabel"] = new[] { "Domains/IPs treated as AI:", "Dominis/IPs considerats IA:", "Dominios/IPs considerados IA:" },

        ["btnAdd"] = new[] { "Add", "Afegeix", "Añadir" },
        ["btnRemove"] = new[] { "Remove", "Treu", "Quitar" },
        ["btnAddExe"] = new[] { "Add .exe…", "Afegeix .exe…", "Añadir .exe…" },
        ["btnBrowse"] = new[] { "Browse…", "Examina…", "Examinar…" },
        ["btnGenerate"] = new[] { "Generate configuration", "Generar configuració", "Generar configuración" },

        ["appsHint"] = new[] { "Allowed executables (e.g. eclipse.exe). Empty = no restriction.", "Executables permesos (p. ex. eclipse.exe). Buit = sense restricció.", "Ejecutables permitidos (ej. eclipse.exe). Vacío = sin restricción." },
        ["extHint"] = new[] { "Allowed extensions, comma-separated (e.g. .java,.txt,.pdf). Empty = no restriction.", "Extensions permeses, separades per comes (p. ex. .java,.txt,.pdf). Buit = sense restricció.", "Extensiones permitidas, separadas por comas (ej. .java,.txt,.pdf). Vacío = sin restricción." },
        ["extBlockHint"] = new[] { "Blocked extensions, comma-separated (e.g. .exe,.zip). Empty = nothing blocked. Disabled when allowed extensions are set (the allow-list is stricter).", "Extensions bloquejades, separades per comes (p. ex. .exe,.zip). Buit = res bloquejat. Es desactiva si hi ha extensions permeses (la llista de permeses és més estricta).", "Extensiones no permitidas, separadas por comas (ej. .exe,.zip). Vacío = no bloquea nada. Se desactiva si hay extensiones permitidas (la lista de permitidas es más estricta)." },
        ["chkRestrict"] = new[] { "Restrict work to a folder and its subfolders", "Restringeix el treball a una carpeta i les seves subcarpetes", "Restringir el trabajo a una carpeta y sus subcarpetas" },
        ["baseLabel"] = new[] { "Folder base (resolved on the student PC):", "Base de la carpeta (es resol a l'equip de l'alumne):", "Base de la carpeta (se resuelve en el equipo del alumno):" },
        ["subLabel"] = new[] { "Optional subfolder (or fixed path):", "Subcarpeta opcional (o ruta fixa):", "Subcarpeta opcional (o ruta fija):" },

        ["comboConfig"] = new[] { "Where exam.config is (recommended)", "On sigui exam.config (recomanat)", "Donde esté exam.config (recomendado)" },
        ["comboDesktop"] = new[] { "Student Desktop", "Escriptori de l'alumne", "Escritorio del alumno" },
        ["comboDocuments"] = new[] { "Student Documents", "Documents de l'alumne", "Documentos del alumno" },
        ["comboFixed"] = new[] { "Fixed path (same on every machine)", "Ruta fixa (igual a tots els equips)", "Ruta fija (igual en todos los equipos)" },

        ["hintConfig"] = new[] { "The student places exam.config inside the exam folder; that folder and its subfolders are watched.", "L'alumne col·loca exam.config dins la carpeta de l'examen; es vigila aquesta carpeta i les seves subcarpetes.", "El alumno coloca exam.config dentro de la carpeta del examen; se vigila esa carpeta y sus subcarpetas." },
        ["hintDesktop"] = new[] { "On each machine: Desktop\\{0}", "A cada equip: Escriptori\\{0}", "En cada equipo: Escritorio\\{0}" },
        ["hintDocuments"] = new[] { "On each machine: Documents\\{0}", "A cada equip: Documents\\{0}", "En cada equipo: Documentos\\{0}" },
        ["hintAbsolute"] = new[] { "That exact path must exist on every laptop (not advised between different users).", "Aquesta ruta exacta ha d'existir a tots els portàtils (no recomanat entre usuaris diferents).", "Esa ruta exacta debe existir en todos los portátiles (no recomendado entre usuarios distintos)." },
        ["allDesktop"] = new[] { "(the whole Desktop folder)", "(tota la carpeta de l'Escriptori)", "(toda la carpeta del Escritorio)" },
        ["allDocuments"] = new[] { "(the whole Documents folder)", "(tota la carpeta de Documents)", "(toda la carpeta de Documentos)" },

        ["valBothPwd"] = new[] { "Both passwords are required.", "Les dues contrasenyes són obligatòries.", "Las dos contraseñas son obligatorias." },
        ["valConfirmA"] = new[] { "Password A does not match its confirmation.", "La contrasenya A no coincideix amb la confirmació.", "La contraseña A no coincide con su confirmación." },
        ["valConfirmB"] = new[] { "Password B does not match its confirmation.", "La contrasenya B no coincideix amb la confirmació.", "La contraseña B no coincide con su confirmación." },
        ["valDistinct"] = new[] { "Passwords A and B must be different.", "Les contrasenyes A i B han de ser diferents.", "Las contraseñas A y B deben ser distintas." },
        ["valFixedPath"] = new[] { "For 'Fixed path' you must enter the folder path.", "Per a 'Ruta fixa' has d'indicar la ruta de la carpeta.", "Para 'Ruta fija' debes indicar la ruta de la carpeta." },
        ["statusGen"] = new[] { "Configuration generated: {0}", "Configuració generada: {0}", "Configuración generada: {0}" },
        ["genOk"] = new[] { "Configuration generated correctly:\n{0}", "Configuració generada correctament:\n{0}", "Configuración generada correctamente:\n{0}" },
        ["genErr"] = new[] { "Error generating configuration:\n{0}", "Error en generar la configuració:\n{0}", "Error al generar la configuración:\n{0}" },
        ["msgTitle"] = new[] { "Exam configuration", "Configuració d'examen", "Configuración de examen" },
        ["dlgSave"] = new[] { "Save exam.config", "Desa exam.config", "Guardar exam.config" },
        ["dlgExe"] = new[] { "Select the allowed executable", "Selecciona l'executable permès", "Selecciona el ejecutable permitido" },
        ["dlgFolder"] = new[] { "Select the exam folder (fixed path, same on every machine)", "Selecciona la carpeta de l'examen (ruta fixa, igual a tots els equips)", "Selecciona la carpeta de examen (ruta fija, igual en todos los equipos)" },
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
