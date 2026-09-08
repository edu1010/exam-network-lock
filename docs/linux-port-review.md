# Revisión del port Linux

La rama Linux incluye el estado de `main` en `04e0648`: contraseñas diferenciadas,
detección de herramientas IA de escritorio y CLI, supervisión de procesos, archivos,
máquinas virtuales y envío de registros al monitor del profesor. Las configuraciones,
contraseñas y el protocolo de registros se comparten mediante `ExamShared`.

Las mejoras de interfaz se aplican al generador y cliente WinForms de esta rama y
al cliente Avalonia: etiquetas completas, botones con tamaño según su contenido,
disposición adaptable y ayudas EN/CA/ES compartidas en `ExamShared/UiHelp.cs`.
La restricción de carpetas está identificada como experimental.

Se corrige el relanzamiento con `pkexec`: la ventana permanece receptiva mientras
se solicita autorización y el proceso de autorización termina tras lanzar el cliente,
sin esperar a que termine la sesión de examen. Los argumentos se pasan por separado
para conservar rutas con espacios. Cancelar la autorización mantiene la ventana actual.
La captura de stdout/stderr ahora drena ambos canales simultáneamente para evitar bloqueos.

## Diferencias de plataforma

- Solo el cliente del alumno está portado a Linux. El generador, monitor y verificador
  gráfico siguen siendo WinForms para Windows.
- Linux usa `nmcli`/`rfkill`, `/proc` y herramientas de audio PulseAudio/PipeWire.
  Su funcionamiento real depende de los permisos y servicios del equipo.
- Linux no enumera la caché DNS: la vigilancia de IA depende de conexiones TCP y
  procesos. No tiene la misma cobertura DNS que Windows.
- La vigilancia de archivos es heurística; no bloquea accesos al sistema de archivos.

## Comprobaciones reproducibles

Validado en Windows: solución completa compilada sin errores ni advertencias,
doce comprobaciones del port y dieciséis de reglas de procesos superadas, además de
publicación autocontenida para `linux-x64`.
La interfaz WinForms se ha renderizado en EN/CA/ES con dos tamaños por aplicación.

```sh
dotnet build ExamLockClient.App/ExamLockClient.App.csproj
dotnet run --project tests/LinuxPortChecks/LinuxPortChecks.csproj
dotnet run --project tests/ProcessPolicyChecks/ProcessPolicyChecks.csproj
dotnet publish ExamLockClient.App/ExamLockClient.App.csproj -c Release -r linux-x64 --self-contained
```

Antes de distribuirlo, probar en un escritorio Linux real: carga de `exam.config`,
cancelación y aceptación de `pkexec`, Wi-Fi/Bluetooth, alarma, notificación al monitor,
reactivación con contraseña y cierre autorizado. La compilación cruzada desde Windows
no valida esas integraciones del sistema operativo.
