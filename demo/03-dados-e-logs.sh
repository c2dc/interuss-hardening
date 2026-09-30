#!/usr/bin/env bash
# Datastore, segredos, cifragem em repouso, WORM, cadeia de hash e redação.
# Rode da raiz do clone. SEM_PAUSA=1 roda direto.
# Uma seção só: "bash 03-dados-e-logs.sh N"  ·  lista de seções: "bash 03-dados-e-logs.sh lista"
source "$(dirname "$0")/lib.sh"
CRDB() { sudo docker exec local_infra_1-1-crdb-1 ./cockroach "$@"; }

if secao 1; then
titulo "1. CockroachDB só aceita mTLS entre nós e clientes"
vivos=$(CRDB node status --certs-dir=/secrets/certs --host=db1.uss1.localutm --format=tsv 2>/dev/null | tail -n +2 | wc -l)
esperado "nós vivos, autenticados por certificado" "$vivos" "2"
msg=$(CRDB sql --insecure --host=db1.uss1.localutm -e "SELECT 1" 2>&1 | grep -o 'node is running secure mode' | head -1)
esperado "ATAQUE: SQL sem certificado" "${msg:+recusado}" "recusado"
nota "quem recusa é o SERVIDOR: \"node is running secure mode, SSL connection required\""
pausa
fi

if secao 2; then
titulo "2. Vault: a chave privada da CA não sai de lá"
code=$(sudo docker exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=dev-root-token \
  local_infra_secrets-openbao-1 bao read pki/root 2>&1 | grep -o 'Code: [0-9]*' | cut -d' ' -f2)
esperado "ATAQUE: ler a chave da CA com o token ROOT" "$code" "405"
nota "405 = a API nem oferece a operação; não é falta de permissão"
pausa
fi

if secao 3; then
titulo "3. Cifragem em repouso: um marcador legível pelo banco, ausente do disco"
MARK="DEMOPROBE$(date +%s)"
CRDB sql --certs-dir=/secrets/certs --host=db1.uss1.localutm -e "
  CREATE DATABASE IF NOT EXISTS demo_probe; CREATE TABLE IF NOT EXISTS demo_probe.t (id INT PRIMARY KEY, v STRING);
  UPSERT INTO demo_probe.t VALUES (1,'$MARK');" >/dev/null 2>&1
CRDB sql --certs-dir=/secrets/certs --host=db1.uss1.localutm \
  -e "SELECT crdb_internal.compact_engine_span(1,1,''::BYTES,'\xff'::BYTES);" >/dev/null 2>&1
lido=$(CRDB sql --certs-dir=/secrets/certs --host=db1.uss1.localutm -e "SELECT v FROM demo_probe.t;" 2>/dev/null | tail -1)
esperado "marcador lido pelo engine" "$([ "$lido" = "$MARK" ] && echo sim || echo nao)" "sim"
hits=$(sudo docker exec local_infra_1-1-crdb-1 grep -rl "$MARK" /cockroach/cockroach-data/ 2>/dev/null | wc -l)
esperado "ocorrências em texto claro no disco" "$hits" "0"
CRDB sql --certs-dir=/secrets/certs --host=db1.uss1.localutm -e "DROP DATABASE demo_probe CASCADE;" >/dev/null 2>&1
nota "o par é o que convence: está no banco E não está legível no disco"
pausa
fi

if secao 4; then
titulo "4. WORM: nem o root da MinIO apaga um log gravado"
MC 'mc retention info --default worm/logs; mc encrypt info worm/logs; mc version info worm/logs' | sed 's/^/    /'
obj=$(MC 'mc ls --recursive worm/logs/interactions/' | awk '{print $NF}' | head -1)
if [ -z "$obj" ]; then obj=$(MC 'mc ls --recursive worm/logs/' | grep -v checkpoints | awk '{print $NF}' | head -1); pref=""; else pref="interactions/"; fi
vid=$(MC "mc ls --versions worm/logs/$pref$obj" | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9a-f]{8}-[0-9a-f]{4}/) print $i}' | head -1)
res=$(MC "mc rm --version-id $vid worm/logs/$pref$obj" | grep -o 'WORM protected' | head -1)
esperado "ATAQUE: root apaga uma versão gravada" "${res:+negado}" "negado"
nota "\"is WORM protected and cannot be overwritten\" — Object Lock COMPLIANCE, 3 dias"
pausa
fi

if secao 5; then
titulo "5. Registros de interação no WORM: token redigido, claims preservados"
# O Vector publica esses registros em lotes de 30 s: espere o lote chegar ao bucket.
conta_interacoes() { MC 'mc ls --recursive worm/logs/interactions/' | grep -c '\.gz'; }
for _ in $(seq 7); do
  [ "$(conta_interacoes)" -gt 0 ] && break
  nota "aguardando o lote do Vector chegar ao WORM (lotes de 30 s)..."; sleep 10
done
if [ "$(conta_interacoes)" -eq 0 ]; then
  # Registros lidos mas presos no buffer em disco do Vector: um novo lote os destrava.
  nota "nada chegou: gerando um lote extra de tráfego para destravar o buffer do Vector..."
  ( cd "$REPO" && CI=true sudo -E monitoring/uss_qualifier/run_locally.sh configurations.dev.general_flight_auth ) >/dev/null 2>&1
  for _ in $(seq 9); do [ "$(conta_interacoes)" -gt 0 ] && break; sleep 10; done
fi
tmp=$(mktemp -d); sudo docker run --rm --network dss_internal_network -v "$SECRETS/minio:/s:ro" -v "$tmp:/out" \
  --entrypoint sh "$MC_IMG" -c 'mkdir -p /root/.mc/certs/CAs && cp /s/ca.crt /root/.mc/certs/CAs/vault-ca.crt
  mc alias set worm https://minio.localutm:9000 "$(cat /s/root_user)" "$(cat /s/root_password)" >/dev/null
  mc mirror --quiet worm/logs/interactions /out' >/dev/null 2>&1
sudo chmod -R a+r "$tmp"
read -r bearer red intact < <(sudo docker run --rm -i -v "$tmp:/a:ro" --entrypoint python3 interuss/monitoring - <<'PY2'
import gzip, glob, re
sig = re.compile(rb'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}')
b = r = i = 0
for f in glob.glob('/a/**/*.gz', recursive=True):
    d = gzip.open(f, 'rb').read(); b += d.count(b'Bearer '); r += d.count(b'REDACTED'); i += len(sig.findall(d))
print(b, r, i)
PY2
)
sudo rm -rf "$tmp"
echo "    headers Bearer: $bearer    assinaturas redigidas: $red"
esperado "há tokens para auditar (rode o qualifier antes)" "$([ "${bearer:-0}" -gt 0 ] && echo sim || echo nao)" "sim"
esperado "Bearer == redigidos (auditoria de TODOS)" "$([ "$bearer" = "$red" ] && echo igual || echo diferente)" "igual"
esperado "JWTs com assinatura intacta" "$intact" "0"
pausa
fi

if secao 6; then
titulo "6. Cadeia de hash sobre o bucket WORM"
verifica_cadeia
esperado "verify-log-chain" "$VERIFICA_RC" "0"
fi
