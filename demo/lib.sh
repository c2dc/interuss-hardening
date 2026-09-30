#!/usr/bin/env bash
# Funções comuns da demonstração. Rode os scripts a partir da RAIZ do clone:
#   cd interuss-hardening && bash /caminho/demo/02-ataques-token.sh
REPO="${REPO:-$(pwd)}"
SECRETS="$REPO/build/dev/dss-secrets"
MC_IMG="local/mc:RELEASE.2025-07-21T05-28-08Z"
if [ ! -d "$SECRETS" ]; then
  echo "ERRO: rode a partir da raiz do clone, com o ambiente de pé (build/dev/dss-secrets não existe)." >&2
  exit 1
fi
export LC_ALL="${LC_ALL:-C.UTF-8}"
B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'

titulo() { echo; echo "${B}${C}━━━ $* ━━━${N}"; }
nota()   { echo "${Y}  » $*${N}"; }
pausa()  { [ -n "${SEM_PAUSA:-}${SECAO:-}" ] && return 0; read -r -p "${Y}  [Enter para continuar]${N} " _; }

# Seleção de seção: "bash 02-ataques-token.sh 3" roda só a seção 3;
# "bash 02-ataques-token.sh lista" mostra as seções; sem argumento, roda tudo.
SECAO="${1:-}"
secao() { [ -z "$SECAO" ] || [ "$SECAO" = "$1" ]; }
if [ "$SECAO" = "lista" ]; then
  grep -o 'titulo "[^"]*"' "$0" | sed 's/^titulo "\(.*\)"$/\1/' | awk '{printf "  %d  %s\n", NR, $0}'
  exit 0
fi

# Compara um valor obtido com o esperado (o esperado aceita alternativas: "404|400").
esperado() {
  local rotulo="$1" obtido="$2" esp="$3"
  local pad=$(( 50 - ${#rotulo} )); (( pad < 1 )) && pad=1
  if [[ "$obtido" =~ ^($esp)$ ]]; then
    printf "  %s%*s%-6s ${G}✓ esperado %s${N}\n" "$rotulo" "$pad" "" "$obtido" "$esp"
  else
    printf "  %s%*s%-6s ${R}✗ esperado %s${N}\n" "$rotulo" "$pad" "" "$obtido" "$esp"
  fi
}

# Código executado DENTRO do container (tem curl, python3, PyJWT, openssl).
read -r -d '' PRELUDIO <<'P'
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
export LC_ALL=C.UTF-8
esperado() {
  local pad=$(( 50 - ${#1} )); (( pad < 1 )) && pad=1
  if [[ "$2" =~ ^($3)$ ]]; then printf "  %s%*s%-6s ${G}✓ esperado %s${N}\n" "$1" "$pad" "" "$2" "$3"
  else printf "  %s%*s%-6s ${R}✗ esperado %s${N}\n" "$1" "$pad" "" "$2" "$3"; fi
}
CA=/secrets/oauth/clients/ca.crt; C=/secrets/oauth/clients
TURL="https://oauth.authority.localutm:8443/token?grant_type=client_credentials"
token() {  # identidade escopo audiencia
  curl -s --cacert $CA --cert $C/$1/crt --key $C/$1/key "$TURL&scope=$2&intended_audience=$3" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'
}
claims() { python3 -c 'import sys,jwt,json; print(json.dumps(jwt.decode(sys.argv[1], options={"verify_signature": False})))' "$1"; }
P

# Executa o script lido da entrada padrão num container interuss/monitoring na rede $1.
na_rede() {
  { echo "$PRELUDIO"; cat; } | sudo docker run --rm -i --network "$1" \
    -v "$SECRETS:/secrets:ro" --entrypoint bash interuss/monitoring -s
}

# Executa comandos mc como ROOT da MinIO (de propósito: nem o root deve conseguir apagar).
MC() {
  sudo docker run --rm -i --network dss_internal_network -v "$SECRETS/minio:/s:ro" \
    --entrypoint sh "$MC_IMG" -c \
    "mkdir -p /root/.mc/certs/CAs && cp /s/ca.crt /root/.mc/certs/CAs/vault-ca.crt;
     mc alias set worm https://minio.localutm:9000 \"\$(cat /s/root_user)\" \"\$(cat /s/root_password)\" >/dev/null;
     $1" 2>&1
}

# Roda make verify-log-chain e devolve o código REAL do script (o make esconde: sempre 2).
verifica_cadeia() {
  local out rc
  out=$(cd "$REPO" && sudo make -s verify-log-chain 2>&1)
  rc=$(printf '%s\n' "$out" | sed -n 's/.*verify_log_chain.sh exit status: \([0-9]\).*/\1/p')
  printf '%s\n' "$out" | grep -E '^(PASS|FAIL|DRIFT|NO CHECKPOINTS|      (expected|recorded|stored|recomputed)|Live bucket)' | sed 's/^/    /'
  VERIFICA_RC="${rc:-0}"
}
