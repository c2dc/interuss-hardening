#!/usr/bin/env bash
# Identidade e tokens: cada controle, o uso legítimo e o ATAQUE que deve falhar.
# Rode da raiz do clone. SEM_PAUSA=1 roda direto.
# Uma seção só: "bash 02-ataques-token.sh N"  ·  lista de seções: "bash 02-ataques-token.sh lista"
source "$(dirname "$0")/lib.sh"

if secao 1; then
titulo "1. F1 — o bypass crítico original: headers forjados, sem certificado"
nota "antes da correção, qualquer peer mintava um JWT como QUALQUER identidade assim"
na_rede interop_ecosystem_network <<'S'
code=$(curl -s -o /dev/null -w '%{http_code}' -m 6 \
  -H "X-SSL-Client-Verify: SUCCESS" -H "X-SSL-Client-CN: CN=uss_qualifier" \
  "http://oauth-signer:8081/token?intended_audience=x&scope=utm.strategic_coordination")
esperado "da rede compartilhada (000 = nem resolve)" "$code" "000"
S
printf "    redes do signer: %s\n" "$(sudo docker inspect local_infra_1-1-oauth-signer-1 --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}')"
na_rede local_infra_1-1_oauth_backend_network <<'S'
code=$(curl -s -o /dev/null -w '%{http_code}' -m 6 \
  -H "X-SSL-Client-Verify: SUCCESS" -H "X-SSL-Client-CN: CN=uss_qualifier" \
  "http://oauth-signer:8081/token?intended_audience=x&scope=utm.strategic_coordination")
esperado "de DENTRO da rede selada, sem o segredo" "$code" "403"
S
nota "duas defesas independentes: isolamento de rede + segredo front→signer"
pausa
fi

if secao 2; then
titulo "2. Emissão: mTLS obrigatório, sub vem do certificado"
na_rede interop_ecosystem_network <<'S'
TOK=$(token uss1 utm.strategic_coordination dss1.uss1.localutm)
claims "$TOK" | python3 -c '
import sys,json; d=json.load(sys.stdin)
for k in ("sub","scope","aud","iss"): print("    %-7s = %s" % (k, d[k]))
print("    exp-iat = %ss   cnf.x5t#S256 = %s..." % (d["exp"]-d["iat"], d["cnf"]["x5t#S256"][:16]))'
code=$(curl -s -o /dev/null -w '%{http_code}' --cacert $CA "$TURL&scope=utm.strategic_coordination&intended_audience=dss1.uss1.localutm")
esperado "pedir token SEM certificado" "$code" "403"
sub=$(curl -s --cacert $CA --cert $C/uss1/crt --key $C/uss1/key \
  "$TURL&scope=utm.strategic_coordination&intended_audience=dss1.uss1.localutm&sub=uss_qualifier" \
  | python3 -c 'import sys,json,jwt; print(jwt.decode(json.load(sys.stdin)["access_token"], options={"verify_signature":False})["sub"])')
esperado "cert uss1 pedindo sub=uss_qualifier → sub" "$sub" "uss1"
S
pausa
fi

if secao 3; then
titulo "3. Menor privilégio: cada identidade só obtém os escopos do seu papel"
na_rede interop_ecosystem_network <<'S'
p() { code=$(curl -s -o /dev/null -w '%{http_code}' --cacert $CA --cert $C/$1/crt --key $C/$1/key \
        "$TURL&intended_audience=dss1.uss1.localutm&scope=$2"); esperado "$1 → $2" "$code" "$3"; }
p uss3          dss.read.identification_service_areas 200
p uss3          utm.strategic_coordination             403
p uss4          rid.display_provider                   403
p uss1          admin.delete_everything                403
p uss_qualifier admin.delete_everything                403
S
pausa
fi

if secao 4; then
titulo "4. RFC 8705: um token roubado não serve sem o certificado"
na_rede interop_ecosystem_network <<'S'
DSSCA=/secrets/dss-tls/uss1/server.crt
D="https://dss1.uss1.localutm/dss/v1/operational_intent_references/f7c3b1a2-4d5e-4f60-8a1b-2c3d4e5f6071"
TOK=$(token uss1 utm.strategic_coordination dss1.uss1.localutm)
q() { curl -s -o /dev/null -w '%{http_code}' -m 15 --cacert "$DSSCA" "$@" "$D"; }
esperado "dono legítimo: token + cert certo (404 = passou)" "$(q --cert $C/uss1/crt --key $C/uss1/key -H "Authorization: Bearer $TOK")" "404|400"
esperado "ladrão: só o token"                              "$(q -H "Authorization: Bearer $TOK")" "403"
esperado "ladrão com o próprio cert (uss3)"                "$(q --cert $C/uss3/crt --key $C/uss3/key -H "Authorization: Bearer $TOK")" "403"
NONE=$(python3 -c 'import sys,jwt; c=jwt.decode(sys.argv[1],options={"verify_signature":False}); print(jwt.encode(c,key=None,algorithm="none"))' "$TOK")
esperado "token forjado alg=none"                          "$(q --cert $C/uss1/crt --key $C/uss1/key -H "Authorization: Bearer $NONE")" "401"
esperado "http:// em texto claro"                          "$(curl -s -o /dev/null -w '%{http_code}' -m 10 "${D/https/http}")" "301"
S
pausa
fi

if secao 5; then
titulo "5. Validação do issuer: trocar SÓ o iss e reassinar com a chave VERDADEIRA"
nota "experimento de variável única: se falhar, falhou pelo iss e mais nada"
na_rede interop_ecosystem_network <<'S'
DSSCA=/secrets/dss-tls/uss1/server.crt
D="https://dss1.uss1.localutm/dss/v1/operational_intent_references/f7c3b1a2-4d5e-4f60-8a1b-2c3d4e5f6071"
export TOK=$(token uss1 utm.strategic_coordination dss1.uss1.localutm)
forja() { python3 - "$1" <<'PY'
import os, sys, jwt
c = jwt.decode(os.environ["TOK"], options={"verify_signature": False})
if sys.argv[1] == "sem": c.pop("iss")
else: c["iss"] = sys.argv[1]
print(jwt.encode(c, open("/secrets/oauth/signing.key","rb").read(), algorithm="RS256",
                 headers={"kid": open("/secrets/oauth/kid").read().strip()}))
PY
}
q() { curl -s -o /dev/null -w '%{http_code}' -m 15 --cacert "$DSSCA" --cert $C/uss1/crt --key $C/uss1/key -H "Authorization: Bearer $1" "$D"; }
esperado "controle: token genuíno"            "$(q "$TOK")" "404|400"
esperado "iss = evil.attacker.example"        "$(q "$(forja evil.attacker.example)")" "401"
esperado "sem claim iss"                      "$(q "$(forja sem)")" "401"
S
pausa
fi

if secao 6; then
titulo "6. A vinculação sobrevive ao load balancer (passthrough TLS)"
nota "confiamos nos DOIS certificados de servidor: o LB alterna entre dss1.uss1 e dss1.uss2"
na_rede interop_ecosystem_network <<'S'
cat /secrets/dss-tls/uss1/server.crt /secrets/dss-tls/uss2/server.crt > /tmp/ambos.crt
LB="https://dss.lb.localutm/dss/v1/operational_intent_references/f7c3b1a2-4d5e-4f60-8a1b-2c3d4e5f6071"
TOK=$(token uss1 utm.strategic_coordination dss.lb.localutm)
q() { curl -s -o /dev/null -w '%{http_code}' -m 15 --cacert /tmp/ambos.crt "$@" "$LB"; }
esperado "via LB, cert certo"   "$(q --cert $C/uss1/crt --key $C/uss1/key -H "Authorization: Bearer $TOK")" "404|400"
esperado "via LB, sem cert"     "$(q -H "Authorization: Bearer $TOK")" "403"
esperado "via LB, cert errado"  "$(q --cert $C/uss3/crt --key $C/uss3/key -H "Authorization: Bearer $TOK")" "403"
S
fi
