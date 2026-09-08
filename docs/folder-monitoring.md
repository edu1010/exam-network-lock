# Restricción de carpeta (experimental)

Esta opción observa indicios de uso de archivos; no impide al sistema ni a las aplicaciones
acceder a sus carpetas. No intercepta todas las lecturas del sistema: examina argumentos
de procesos nuevos de aplicaciones que abren documentos y altas/renombrados dentro de la carpeta de trabajo.

Para reducir falsos avisos:

- Se mantienen las exclusiones existentes de temporales, cachés y configuración del usuario
  fuera de la carpeta de trabajo. Los archivos dentro de la carpeta elegida se comprueban
  aunque esta esté en un directorio temporal.
- Se distinguen opciones concretas de arranque de Eclipse, Java, VS Code y navegadores
  (bibliotecas de arranque, classpath, perfiles y logs) de los documentos que se abren.
  Las excepciones se aplican solo a la aplicación correspondiente.
- Crear o renombrar metadatos concretos de `.idea` y `.vscode` no genera avisos de extensión
  desconocida. No se excluyen esas carpetas enteras. Abrir esos archivos explícitamente sigue
  comprobándose y una extensión expresamente prohibida tiene prioridad.
- Los directorios con puntos en el nombre no se tratan como archivos. En Linux se respeta
  la distinción entre mayúsculas y minúsculas al comparar rutas.

Continúa siendo una heurística: pueden quedar falsos avisos de otros auxiliares y no detecta
todas las aperturas realizadas desde aplicaciones ya abiertas. Las exclusiones de caché
tampoco son una garantía frente a usos deliberados de esas ubicaciones. Probar con el IDE
y las aplicaciones del aula antes del examen; revisar el archivo y el contexto del aviso.

Pruebas: `dotnet run --project tests/FileActivityChecks/FileActivityChecks.csproj` en cada rama.
