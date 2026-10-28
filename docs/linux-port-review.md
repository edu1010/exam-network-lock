# Revisión del port Linux

La rama `linux` incluye todo `main` (último merge: guía del profesorado, `e9d816c`) y añade
versiones Avalonia de las **cuatro** aplicaciones: cliente del alumno, generador, monitor y
verificador con interfaz. Configuración, contraseñas, registros y protocolo de red se comparten
mediante `ExamShared`; los textos (`Lang.cs`) y la clasificación de eventos (`EventCatalog.cs`) se
enlazan desde los proyectos WinForms, de modo que no se duplican.

## Privilegios

- **El alumno no necesita sudo.** Todo el cliente se ejecuta como el usuario de la sesión.
- Wi-Fi: `nmcli radio wifi off` (NetworkManager lo permite al usuario activo; ver
  `nmcli general permissions`) y, si falla, `rfkill` (buscado también en `/usr/sbin`; `/dev/rfkill`
  tiene ACL `uaccess` para el usuario de la sesión).
- Bluetooth: `rfkill` y, si no, `bluetoothctl power off`. Un equipo sin adaptador cuenta como
  desactivado. Todas las órdenes externas tienen tiempo límite (p. ej. `bluetoothctl` se queda
  colgado si `bluetoothd` no está activo).
- Solo si el bloqueo sin privilegios falla aparece **Bloquear radios (admin)**: lanza `pkexec` con
  un script fijo que únicamente ejecuta `nmcli`/`rfkill` como root. El programa no se reabre como
  root. Al final, la contraseña A/B vuelve a activar las radios (con `pkexec` si se bloquearon así).
- polkit pide la contraseña de administrador (en estos equipos, la de root o de un usuario del grupo
  `sudo`): la teclea el profesorado.

## Validación en Debian 12 (bookworm, X11, usuario LDAP sin sudo)

- Solución completa compilada (`-p:EnableWindowsTargeting=true` para los proyectos WinForms).
- `LinuxPortChecks` (14), `ProcessPolicyChecks` y `FileActivityChecks` superados.
- Binarios portables lanzados con entorno mínimo (`env -i`, sin .NET en el PATH): los cuatro abren.
- Flujo real: el cliente desactiva Wi-Fi como usuario, detecta un programa prohibido y una conexión
  a IA, el monitor recibe estado y registro (integridad OK), la contraseña A reactiva la Wi-Fi y la
  B cierra con `NORMAL_EXIT`. El verificador marca registros íntegros, con incidencias y manipulados.
- Fallo simulado de `nmcli`: aparece el aviso amarillo y el botón; `pkexec` muestra el diálogo de
  polkit y cancelarlo deja el cliente funcionando.

## Limitaciones conocidas

- Linux no enumera la caché DNS: la vigilancia de IA depende de conexiones TCP y procesos.
- Sin root no se puede atribuir a un proceso las conexiones de **otros** usuarios; aparecen como
  aviso no atribuido. Las del propio alumno sí se atribuyen.
- La vigilancia de archivos es heurística (inotify); no bloquea accesos.
- Arrastrar y soltar en el verificador depende del soporte XDND de Avalonia; los botones
  «Añadir registros/carpeta» y pasar rutas por línea de órdenes funcionan siempre.
