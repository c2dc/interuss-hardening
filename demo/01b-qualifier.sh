#!/usr/bin/env bash
# Configurações reais do uss_qualifier (~35 s no total):
#   minimal_probing     — cenários contra os dois DSS
#   general_flight_auth — planejamento de voo através dos mocks; gera os registros
#                         de interação ASTM que a demo de redação (03, seção 5) audita
#                         (roda DUAS vezes: o 1º lote após a subida às vezes fica preso
#                         no buffer em disco do Vector até chegar o próximo)
source "$(dirname "$0")/lib.sh"
for CFG in ${@:-minimal_probing general_flight_auth general_flight_auth}; do
titulo "uss_qualifier: configurations.dev.$CFG"
log=$(mktemp)
( cd "$REPO" && CI=true sudo -E monitoring/uss_qualifier/run_locally.sh "configurations.dev.$CFG" ) 2>&1 | tee "$log" \
  | grep --line-buffered -oE 'Running "[^"]+" scenario|Validating test run report|Validation failed[^|]*' \
  | sed -u 's/^Running "\(.*\)" scenario$/    ▸ \1/; s/^Validat/    ● Validat/'
rc=${PIPESTATUS[0]}
esperado "exit code" "$rc" "0"
esperado "relatório validado"      "$(grep -q 'Validating test run report' "$log" && echo sim || echo nao)" "sim"
esperado "sem falha de validação"  "$(grep -q 'Validation failed on test run report' "$log" && echo falhou || echo ok)" "ok"
nota "exit 0 sozinho NÃO basta: config sem bloco validation sai 0 mesmo com falhas"
echo "    relatório HTML: $REPO/monitoring/uss_qualifier/output/$CFG/"
rm -f "$log"
done
