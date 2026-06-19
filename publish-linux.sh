#!/usr/bin/env bash
# ============================================================================
#  publish-linux.sh - Genera el ejecutable Linux self-contained (con .NET
#  embebido) del cliente del alumno en dist-linux/.
#
#  Solo el cliente multiplataforma (ExamLockClient.App, Avalonia) tiene sentido
#  en Linux: ExamConfigGenerator/ExamMonitor/ExamLogVerifierUI son WinForms y se
#  quedan en Windows (usa publish.cmd para esos). El .exe lleva el runtime de
#  .NET dentro, asi que corre en maquinas sin .NET instalado.
#
#  Uso opcional:  ./publish-linux.sh [RID]   (por defecto linux-x64)
#  Ejemplos:      ./publish-linux.sh             -> linux-x64
#                 ./publish-linux.sh linux-arm64 -> ARM64 (ej. Raspberry/portatiles ARM)
# ============================================================================
set -euo pipefail

# Situarse en la carpeta del script para que las rutas sean relativas a el.
cd "$(dirname "$0")"

RID="${1:-linux-x64}"
PROJECT="ExamLockClient.App/ExamLockClient.App.csproj"
OUTDIR="dist-linux/ExamLockClient.App"

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
    echo "[ERROR] No se encontro 'dotnet'. Instala el .NET 8 SDK desde https://dotnet.microsoft.com/download" >&2
    exit 1
  fi
fi

echo "============================================================"
echo " Publicando exam-network-lock (cliente Linux)  |  RID: $RID"
echo " Salida: $(pwd)/dist-linux"
echo "============================================================"
echo

# --- Limpiar salida anterior para que dist-linux solo tenga lo nuevo ---
rm -rf dist-linux

echo "--- ExamLockClient.App ..."
"$DOTNET" publish "$PROJECT" -c Release -r "$RID" --self-contained true \
  -p:DebugType=none -p:DebugSymbols=false -o "$OUTDIR" --nologo -v minimal

# Asegurar el bit de ejecucion del binario nativo.
if [ -f "$OUTDIR/ExamLockClient.App" ]; then
  chmod +x "$OUTDIR/ExamLockClient.App"
fi

echo
echo "============================================================"
echo " Listo. Ejecutable generado:"
echo "============================================================"
if [ -f "$OUTDIR/ExamLockClient.App" ]; then
  ls -lh "$OUTDIR/ExamLockClient.App" | awk '{print $5"\t"$9}'
else
  ls -lh "$OUTDIR"
fi
echo
echo "Para ejecutarlo en el equipo del alumno:"
echo "  cp exam.config \"$OUTDIR/\"            # opcional: junto al binario"
echo "  \"$OUTDIR/ExamLockClient.App\""
