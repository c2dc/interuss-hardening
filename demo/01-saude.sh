#!/usr/bin/env bash
# O ambiente subiu inteiro? Rode da raiz do clone.
# Uma seção só: "bash 01-saude.sh N"  ·  lista de seções: "bash 01-saude.sh lista"
source "$(dirname "$0")/lib.sh"

if secao 1; then
titulo "Containers"
n=$(sudo docker ps -q | wc -l)
esperado "containers rodando" "$n" "21"
ruins=$(sudo docker ps -a --format '{{.Names}} {{.Status}}' | grep -Eci 'unhealthy|restarting')
esperado "unhealthy / reiniciando" "$ruins" "0"
sudo docker ps --format '{{.Names}}\t{{.Status}}' | sort | sed 's/^/    /'
pausa
fi

if secao 2; then
titulo "Três planos de rede"
for net in interop_ecosystem_network dss_internal_network local_infra_1-1_oauth_backend_network; do
  printf "    %-42s internal=%s  containers=%s\n" "$net" \
    "$(sudo docker network inspect "$net" --format '{{.Internal}}')" \
    "$(sudo docker network inspect "$net" --format '{{len .Containers}}')"
done
nota "o signer de tokens vive SOZINHO numa rede internal: só o front OAuth o alcança"
pausa
fi

if secao 3; then
titulo "Imagens construídas localmente (nada disto é baixado pronto)"
sudo docker images --format '{{.Repository}}:{{.Tag}}  {{.Size}}' | grep -E 'interuss/monitoring|local/' | sed 's/^/    /'
printf "    versão embutida: "; sudo docker run --rm --entrypoint sh interuss/monitoring -c 'echo $MONITORING_VERSION'
fi
