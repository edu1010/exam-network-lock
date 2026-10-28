#!/usr/bin/env bash
# ============================================================================
#  publish-linux.sh - Genera los ejecutables Linux portables (self-contained,
#  un solo fichero, con .NET embebido) de las cuatro aplicaciones en dist-linux/.
#
#    ExamLockClient       cliente del alumno (no necesita sudo)
#    ExamConfigGenerator  generador de exam.config (profesorado)
#    ExamMonitor          monitor en vivo por la LAN (profesorado)
#    ExamLogVerifierUI    verificador de registros (profesorado)
#
#  Son versiones Avalonia de las apps WinForms (publish.cmd sigue generando las
#  de Windows). No requieren .NET instalado ni permisos de administrador.
#
#  Uso opcional:  ./publish-linux.sh [RID]   (por defecto linux-x64)
#  Ejemplos:      ./publish-linux.sh             -> linux-x64
#                 ./publish-linux.sh linux-arm64 -> ARM64 (ej. Raspberry/portatiles ARM)
# ============================================================================
set -euo pipefail

# Situarse en la carpeta del script para que las rutas sean relativas a el.
cd "$(dirname "$0")"

RID="${1:-linux-x64}"
OUTDIR="dist-linux"

# proyecto:nombre-final-del-ejecutable
APPS=(
  "ExamLockClient.App:ExamLockClient"
  "ExamConfigGenerator.App:ExamConfigGenerator"
  "ExamMonitor.App:ExamMonitor"
  "ExamLogVerifierUI.App:ExamLogVerifierUI"
)

# --- Localizar dotnet (PATH o rutas por defecto) ---
DOTNET="dotnet"
if ! command -v dotnet >/dev/null 2>&1; then
  if [ -x "$HOME/.dotnet/dotnet" ]; then
    DOTNET="$HOME/.dotnet/dotnet"
  elif [ -x "/usr/share/dotnet/dotnet" ]; then
    DOTNET="/usr/share/dotnet/dotnet"
  elif [ -x "/usr/lib/dotnet/dotnet" ]; then
    DOTNET="/usr/lib/dotnet/dotnet"
  else
    echo "[ERROR] No se encontro 'dotnet'. Instala el .NET 8 SDK (sin sudo):" >&2
    echo "  curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0" >&2
    exit 1
  fi
fi

echo "============================================================"
echo " Publicando exam-network-lock (Linux)  |  RID: $RID"
echo " Salida: $(pwd)/$OUTDIR"
echo "============================================================"
echo

# --- Limpiar salida anterior para que dist-linux solo tenga lo nuevo ---
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for entry in "${APPS[@]}"; do
  PROJECT="${entry%%:*}"
  NAME="${entry##*:}"
  echo "--- $PROJECT -> $NAME"
  "$DOTNET" publish "$PROJECT/$PROJECT.csproj" -c Release -r "$RID" --self-contained true \
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
    -p:DebugType=none -p:DebugSymbols=false -o "$TMP/$PROJECT" --nologo -v minimal

  # El binario nativo se llama como el ensamblado; se copia con su nombre final.
  BIN="$(find "$TMP/$PROJECT" -maxdepth 1 -type f -perm -u+x ! -name '*.so' ! -name '*.dll' | head -n 1)"
  if [ -z "$BIN" ]; then
    echo "[ERROR] No se encontro el ejecutable publicado de $PROJECT" >&2
    exit 1
  fi
  cp "$BIN" "$OUTDIR/$NAME"
  chmod +x "$OUTDIR/$NAME"
done

echo
echo "============================================================"
echo " Listo. Ejecutables generados:"
echo "============================================================"
ls -lh "$OUTDIR" | awk 'NR>1 {print $5"\t"$9}'
echo
echo "En el equipo del alumno (sin sudo):"
echo "  cp exam.config <carpeta>/ && <carpeta>/ExamLockClient --config <carpeta>/exam.config"
echo "  (o deja exam.config junto al binario / en la carpeta actual y ejecuta ./ExamLockClient)"
