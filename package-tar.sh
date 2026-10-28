#!/usr/bin/env bash
# ============================================================================
#  package-tar.sh - Empaqueta cada ejecutable Linux de dist-linux/ en su propio
#  .tar.gz (uno por aplicacion).
#
#  Un binario suelto pierde el permiso de ejecucion al bajarlo de Google Drive;
#  dentro de un .tar.gz lo conserva. No hace falta sudo ni chmod:
#      tar -xzf ExamLockClient-linux-x64.tar.gz      (o doble clic -> Extraer)
#      ./ExamLockClient/ExamLockClient
#
#  Uso:  ./publish-linux.sh && ./package-tar.sh [RID]   (por defecto linux-x64)
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

RID="${1:-linux-x64}"
SRC="dist-linux"
APPS=(ExamLockClient ExamConfigGenerator ExamMonitor ExamLogVerifierUI)

for APP in "${APPS[@]}"; do
  if [ ! -f "$SRC/$APP" ]; then
    echo "[ERROR] Falta $SRC/$APP. Ejecuta antes ./publish-linux.sh" >&2
    exit 1
  fi
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

for APP in "${APPS[@]}"; do
  # Cada archivo se extrae en su propia carpeta para no mezclar ficheros.
  mkdir -p "$STAGE/$APP"
  install -m 0755 "$SRC/$APP" "$STAGE/$APP/$APP"
  OUT="$SRC/$APP-$RID.tar.gz"
  tar -C "$STAGE" --owner=0 --group=0 -czf "$OUT" "$APP"
  echo "Paquete generado: $OUT ($(du -h "$OUT" | cut -f1))"
done
