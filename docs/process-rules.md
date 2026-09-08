# Programas permitidos y prohibidos

Ambas listas vigilan nombres de ejecutables; no cierran procesos ni bloquean su ejecución.
Se pueden escribir nombres como `firefox`, `firefox.exe` o `code`. Se normalizan las rutas,
mayúsculas y sufijos `.exe`/`.bin`; las diferencias reales entre nombres de aplicaciones
en Windows y Linux requieren entradas separadas.

- **Prohibidos**: incidencia roja, aunque el programa ya esté abierto al iniciar el examen.
  Tiene prioridad sobre permitidos y sobre las excepciones por nombre del sistema.
- **Permitidos**: si la lista está llena, un proceso nuevo que no figure en ella genera
  un aviso ámbar. Los procesos ya abiertos y una lista de procesos habituales del sistema
  quedan exentos. No es un inventario completo de los servicios de cada equipo: auxiliares
  de IDE, actualizaciones o software del centro pueden producir avisos.
- **Solo prohibidos**: dejar permitidos vacío para vigilar aplicaciones concretas sin
  generar avisos por otros procesos. Las comprobaciones independientes de IA y VM siguen activas.

Las reglas son heurísticas por nombre, no identifican de forma segura el ejecutable ni
detectan todos los procesos de vida corta. Conviene probar una lista de permitidos con el
software real del aula antes del examen.

Los clientes nuevos siguen leyendo configuraciones anteriores: el campo opcional
`blockedProcesses` se omite cuando no se utiliza, conservando la representación firmada.
Las configuraciones que lo incluyan requieren los clientes y verificadores actualizados.

Comprobaciones: `dotnet run --project tests/ProcessPolicyChecks/ProcessPolicyChecks.csproj`.
