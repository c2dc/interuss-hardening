#!/usr/bin/env bash
# Subida do ZERO, com tempo por etapa. Dispare nos primeiros minutos, num terminal
# separado, e volte à teoria: leva ~2,5 min numa máquina de 12 CPUs com as imagens
# de terceiros em cache, e até ~10 min numa máquina modesta sem cache.
#
#   bash 00-subida.sh [diretório-destino]      (padrão: ~/demo)
set -o pipefail
DEST="${1:-$HOME/demo}"
URL="https://github.com/c2dc/interuss-hardening"
B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'
inicio=$(date +%s)
etapa() {  # rótulo, comando...
  local rot="$1"; shift
  local t0; t0=$(date +%s)
  echo "${B}${C}▶ $rot${N}   ($*)"
  if "$@" > "$DEST/log-$(echo "$rot" | tr ' /' '__').txt" 2>&1; then
    echo "  ${G}✓ $rot — $(( $(date +%s) - t0 ))s${N}"
  else
    echo "  ${R}✗ $rot falhou — veja $DEST/log-$(echo "$rot" | tr ' /' '__').txt${N}"; exit 1
  fi
}
mkdir -p "$DEST"; cd "$DEST" || exit 1
[ -d interuss-hardening ] && { echo "${R}$DEST/interuss-hardening já existe — use outro destino.${N}"; exit 1; }

etapa "1 git clone"             git clone -q "$URL"
cd interuss-hardening || exit 1
etapa "2 submodulos"            git submodule update --init
# O build vem ANTES do start-locally de propósito: o oauth-signer (que tem a chave de
# assinatura montada) roda sobre a imagem interuss/monitoring. Ela é sempre construída
# localmente e nunca baixada — senão viria a upstream :latest, sem versão fixada.
# O start-locally também a constrói; aqui fica explícito para a plateia.
etapa "3 build interuss-monitoring" sudo ./monitoring/build.sh
etapa "4 start-locally (vault, WORM, DSS, OAuth, LB; compila MinIO)" sudo make start-locally
etapa "5 start-uss-mocks"       sudo make start-uss-mocks

echo
echo "${B}${G}Ambiente de pé em $(( $(date +%s) - inicio ))s — $(sudo docker ps -q | wc -l) containers (esperado: 21).${N}"
echo "Próximo: cd $DEST/interuss-hardening"
