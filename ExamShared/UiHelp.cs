namespace ExamShared;

/// <summary>Shared hover help for the Windows generator and both student clients (EN/CA/ES).</summary>
public static class UiHelp
{
    public static string Get(string key, int language) =>
        Text.TryGetValue(key, out var values) ? values[Math.Clamp(language, 0, 2)] : string.Empty;

    private static readonly Dictionary<string, string[]> Text = new()
    {
        ["pwdA"] = ["Password used to re-enable Wi-Fi for submission. The program stays open.", "Contrasenya per tornar a habilitar el Wi-Fi i lliurar l'examen. El programa continua obert.", "Contraseña para rehabilitar Wi-Fi y entregar el examen. El programa sigue abierto."],
        ["pwdAc"] = ["Repeat the Wi-Fi password to check for typing mistakes.", "Repeteix la contrasenya del Wi-Fi per comprovar que és correcta.", "Repite la contraseña de Wi-Fi para comprobar que está bien escrita."],
        ["pwdB"] = ["Teacher password used to end the session and close the program.", "Contrasenya del professor per finalitzar la sessió i tancar el programa.", "Contraseña del profesor para finalizar la sesión y cerrar el programa."],
        ["pwdBc"] = ["Repeat the password used to close the program. It must differ from the Wi-Fi password.", "Repeteix la contrasenya per tancar el programa. Ha de ser diferent de la del Wi-Fi.", "Repite la contraseña para cerrar el programa. Debe ser distinta de la de Wi-Fi."],
        ["chkWifi"] = ["Try to switch off Wi-Fi when the exam starts. System permissions are required.", "Intenta desactivar el Wi-Fi en començar l'examen. Calen permisos del sistema.", "Intenta desactivar Wi-Fi al comenzar el examen. Requiere permisos del sistema."],
        ["chkBt"] = ["Try to switch off Bluetooth when the exam starts.", "Intenta desactivar el Bluetooth en començar l'examen.", "Intenta desactivar Bluetooth al comenzar el examen."],
        ["chkAi"] = ["Watch connections to the listed AI domains and detect dedicated AI tools.", "Vigila connexions als dominis d'IA indicats i detecta eines dedicades d'IA.", "Vigila conexiones a los dominios de IA indicados y detecta herramientas dedicadas de IA."],
        ["chkVol"] = ["Enable audible alerts when AI activity is detected.", "Activa els avisos sonors quan es detecta activitat d'IA.", "Activa avisos sonoros al detectar actividad de IA."],
        ["chkVm"] = ["Report signs of virtual machines or virtualization tools.", "Informa d'indicis de màquines virtuals o eines de virtualització.", "Informa de indicios de máquinas virtuales o herramientas de virtualización."],
        ["chkMonitor"] = ["Send session status and logs to the teacher monitor over the local network.", "Envia l'estat i els registres al monitor del professor per la xarxa local.", "Envía el estado y los registros al monitor del profesor por la red local."],
        ["monitorTargetsLabel"] = ["Teacher computer IPv4 addresses, separated by commas. Leave empty for automatic LAN discovery.", "Adreces IPv4 dels equips del professor, separades per comes. Buit per descobrir-los a la xarxa local.", "Direcciones IPv4 de los equipos del profesor, separadas por comas. Vacío para descubrirlos en la red local."],
        ["btnUseCurrentIp"] = ["Fill in this computer's active IPv4 address. Use it when the teacher monitor runs here.", "Omple l'adreça IPv4 activa d'aquest equip. Usa-la si el monitor del professor s'executa aquí.", "Rellena la IPv4 activa de este equipo. Úsala si el monitor del profesor se ejecuta aquí."],
        ["beepModeLabel"] = ["Choose a continuous alarm or three beeps for each incident.", "Tria una alarma contínua o tres xiulets per incidència.", "Elige una alarma continua o tres pitidos por incidencia."],
        ["volumeLabel"] = ["Set the volume used by the exam alarm.", "Ajusta el volum de l'alarma de l'examen.", "Ajusta el volumen de la alarma del examen."],
        ["aiListLabel"] = ["AI domains to watch, including their subdomains. Add a domain without https:// or a page path.", "Dominis d'IA a vigilar, inclosos els subdominis. Afegeix un domini sense https:// ni ruta.", "Dominios de IA que se vigilan, incluidos sus subdominios. Añade un dominio sin https:// ni ruta."],
        ["appsHint"] = ["Executable names allowed during the exam. An empty list leaves programs unrestricted.", "Noms dels executables permesos durant l'examen. Una llista buida no restringeix programes.", "Nombres de ejecutables permitidos durante el examen. Una lista vacía no restringe programas."],
        ["extHint"] = ["Allow only these file extensions, separated by commas. This takes priority over blocked extensions.", "Permet només aquestes extensions, separades per comes. Té prioritat sobre les extensions bloquejades.", "Permite solo estas extensiones, separadas por comas. Tiene prioridad sobre las extensiones bloqueadas."],
        ["extBlockHint"] = ["Report these file extensions. Available only when the allowed-extension list is empty.", "Informa d'aquestes extensions. Disponible només si la llista d'extensions permeses és buida.", "Informa de estas extensiones. Disponible solo si la lista de extensiones permitidas está vacía."],
        ["chkRestrict"] = ["Experimental: monitor file activity outside the work folder. This is not a filesystem access lock.", "Experimental: vigila l'activitat de fitxers fora de la carpeta de treball. No bloqueja l'accés al sistema de fitxers.", "Experimental: vigila la actividad de archivos fuera de la carpeta de trabajo. No bloquea el acceso al sistema de archivos."],
        ["baseLabel"] = ["Choose how the work folder is located on each student's computer.", "Tria com es localitza la carpeta de treball a l'equip de cada alumne.", "Elige cómo localizar la carpeta de trabajo en el equipo de cada alumno."],
        ["subLabel"] = ["Optional folder relative to the selected base, or a full path when using Fixed path.", "Carpeta opcional relativa a la base, o una ruta completa si tries Ruta fixa.", "Carpeta opcional relativa a la base, o una ruta completa si eliges Ruta fija."],
        ["btnBrowse"] = ["Select a folder on this computer and use its fixed path.", "Selecciona una carpeta d'aquest equip i usa'n la ruta fixa.", "Selecciona una carpeta de este equipo y utiliza su ruta fija."],
        ["btnAddExe"] = ["Choose an executable and add its filename to the allowed programs.", "Tria un executable i afegeix-ne el nom als programes permesos.", "Elige un ejecutable y añade su nombre a los programas permitidos."],
        ["btnAdd"] = ["Add the text from the adjacent field to this list.", "Afegeix el text del camp adjacent a aquesta llista.", "Añade el texto del campo contiguo a esta lista."],
        ["btnRemove"] = ["Remove the selected item from this list.", "Treu l'element seleccionat d'aquesta llista.", "Quita el elemento seleccionado de esta lista."],
        ["btnGenerate"] = ["Validate the settings and save exam.config for distribution to students.", "Valida les opcions i desa exam.config per distribuir-lo als alumnes.", "Valida las opciones y guarda exam.config para distribuirlo al alumnado."],
        ["loadBtn"] = ["Choose the exam.config supplied by the teacher to start the exam session.", "Tria l'exam.config del professor per iniciar la sessió d'examen.", "Elige el exam.config del profesor para iniciar la sesión de examen."],
        ["reopenAdminBtn"] = ["Request system administrator permissions and reopen the client.", "Demana permisos d'administrador del sistema i reobre el client.", "Solicita permisos de administrador del sistema y vuelve a abrir el cliente."],
        ["incidents"] = ["Session events and detected violations appear here.", "Aquí apareixen els esdeveniments de la sessió i les infraccions detectades.", "Aquí aparecen los eventos de la sesión y las infracciones detectadas."],
        ["radios"] = ["Current Wi-Fi and Bluetooth state reported by the operating system.", "Estat actual del Wi-Fi i Bluetooth segons el sistema operatiu.", "Estado actual de Wi-Fi y Bluetooth según el sistema operativo."],
        ["shield"] = ["Green: protected. Amber: attention required. Red: incident detected.", "Verd: protegit. Ambre: cal atenció. Vermell: incidència detectada.", "Verde: protegido. Ámbar: requiere atención. Rojo: incidencia detectada."],
    };
}
