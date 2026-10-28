#!/usr/bin/env bash
# ============================================================================
#  package-deb.sh - Empaqueta los ejecutables Linux de dist-linux/ en un .deb.
#
#  Un .deb conserva los permisos de ejecucion aunque pase por Google Drive,
#  correo, etc. (un binario suelto los pierde al descargarlo).
#
#  Instalacion (con sudo, p. ej. el profesorado o el admin del aula):
#      sudo apt install ./exam-network-lock_<version>_amd64.deb
#  Sin sudo (alumnado): extraer sin instalar, los permisos se mantienen:
#      dpkg -x exam-network-lock_<version>_amd64.deb ~/examen
#      ~/examen/opt/exam-network-lock/ExamLockClient
#
#  Uso:  ./publish-linux.sh && ./package-deb.sh [version]   (por defecto 2.6.0)
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-2.6.0}"
ARCH="amd64"
PKG="exam-network-lock"
SRC="dist-linux"
OUT="$SRC/${PKG}_${VERSION}_${ARCH}.deb"

# binario:comando:nombre-en-menu:descripcion
APPS=(
  "ExamLockClient:exam-lock-client:Exam Lock Client (alumno):Escudo del examen para el alumnado"
  "ExamConfigGenerator:exam-config-generator:Exam Config Generator:Crea exam.config (profesorado)"
  "ExamMonitor:exam-monitor:Exam Monitor:Supervisa al alumnado por la red (profesorado)"
  "ExamLogVerifierUI:exam-log-verifier:Exam Log Verifier:Verifica los registros del examen (profesorado)"
)

for entry in "${APPS[@]}"; do
  BIN="${entry%%:*}"
  if [ ! -f "$SRC/$BIN" ]; then
    echo "[ERROR] Falta $SRC/$BIN. Ejecuta antes ./publish-linux.sh" >&2
    exit 1
  fi
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/root"
mkdir -p "$ROOT/DEBIAN" "$ROOT/opt/$PKG" "$ROOT/usr/bin" "$ROOT/usr/share/applications" \
  "$ROOT/usr/share/icons/hicolor/256x256/apps"

# Icono: la imagen mas grande del .ico de Windows.
if command -v convert >/dev/null 2>&1; then
  convert "branding/app.ico[-1]" -resize 256x256 "$ROOT/usr/share/icons/hicolor/256x256/apps/$PKG.png"
fi

for entry in "${APPS[@]}"; do
  IFS=: read -r BIN CMD NAME COMMENT <<<"$entry"
  install -m 0755 "$SRC/$BIN" "$ROOT/opt/$PKG/$BIN"
  ln -s "/opt/$PKG/$BIN" "$ROOT/usr/bin/$CMD"
  cat > "$ROOT/usr/share/applications/$CMD.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$NAME
Comment=$COMMENT
Exec=/opt/$PKG/$BIN %F
Icon=$PKG
Terminal=false
Categories=Education;
EOF
done

SIZE_KB="$(du -sk "$ROOT/opt" | cut -f1)"
cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Architecture: $ARCH
Maintainer: edu1010 <edu1010@users.noreply.github.com>
Installed-Size: $SIZE_KB
Section: education
Priority: optional
Recommends: network-manager, pulseaudio-utils | pipewire-pulse, pkexec | policykit-1
Homepage: https://github.com/edu1010/exam-network-lock
Description: Exam Network Lock - bloqueo y supervision de examenes (Linux)
 Cliente del alumno (no necesita sudo), generador de exam.config, monitor del
 profesor por la LAN y verificador de registros. Ejecutables autocontenidos:
 no requieren .NET instalado.
EOF

dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$OUT" >/dev/null
echo "Paquete generado: $OUT ($(du -h "$OUT" | cut -f1))"
