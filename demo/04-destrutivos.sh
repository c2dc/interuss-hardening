#!/usr/bin/env bash
# DESTRUTIVO. Três ataques contra a trilha de auditoria, cada um DETECTADO.
# Deixa o ambiente sujo de forma irreversível (um checkpoint forjado não pode ser
# apagado — Object Lock). Ao final: sudo make restart-all.
# Uma seção só: "bash 04-destrutivos.sh N"  ·  lista de seções: "bash 04-destrutivos.sh lista"
source "$(dirname "$0")/lib.sh"

if secao 1; then
titulo "Antes: cadeia íntegra"
verifica_cadeia; esperado "verify-log-chain" "$VERIFICA_RC" "0"
pausa
fi

if secao 2; then
titulo "D1 — root rebaixa a retenção do bucket (COMPLIANCE 3d → GOVERNANCE 1d)"
MC 'mc retention set --default governance 1d worm/logs' | sed 's/^/    /'
verifica_cadeia; esperado "checagem ao vivo: drift (exit 2)" "$VERIFICA_RC" "2"
nota "aguardando o chainer gravar o drift DENTRO de um checkpoint imutável (até ~60 s)..."
antes=$(sudo docker logs local_infra_secrets-log-chainer-1 2>&1 | grep -c 'WARNING.*drift')
until [ "$(sudo docker logs local_infra_secrets-log-chainer-1 2>&1 | grep -c 'WARNING.*drift')" -gt "$antes" ]; do sleep 3; done
sleep 2
sudo docker logs local_infra_secrets-log-chainer-1 2>&1 | grep 'checkpoint .* written' | tail -1 | sed 's/^/    /'
verifica_cadeia; esperado "drift registrado na cadeia (exit 2)" "$VERIFICA_RC" "2"
nota "restaurar a política NÃO apaga a evidência: ela está num checkpoint imutável"
pausa
fi

if secao 3; then
titulo "D2 — encobrir: reescrever a linha de retenção do checkpoint, header intacto"
alvo=$(MC 'mc ls worm/logs/checkpoints/' | awk '{print $NF}' | sort | tail -1)
echo "    alvo: $alvo"
MC "mc cat worm/logs/checkpoints/$alvo > /tmp/c.txt
    printf '    antes : '; head -n5 /tmp/c.txt | tail -n1
    { head -n4 /tmp/c.txt; echo 'retention COMPLIANCE 3DAYS'; tail -n +6 /tmp/c.txt; } > /tmp/f.txt
    printf '    depois: '; head -n5 /tmp/f.txt | tail -n1
    mc pipe worm/logs/checkpoints/$alvo < /tmp/f.txt >/dev/null && echo '    forja gravada como nova versão do objeto'"
verifica_cadeia; esperado "cadeia quebrada (exit 1 supera drift)" "$VERIFICA_RC" "1"
nota "a retenção fica DENTRO do corpo com hash: editar a linha muda o sha256"
pausa
fi

if secao 4; then
titulo "D3 — apagar a trilha inteira: todos os checkpoints"
MC 'mc rm --recursive --force worm/logs/checkpoints/' | tail -1 | sed 's/^/    /'
verifica_cadeia; esperado "cadeia vazia falha FECHADA (exit 1)" "$VERIFICA_RC" "1"
nota "e a checagem de retenção ao vivo continua rodando: apagar a trilha não desliga o alarme"
echo
echo "${Y}  Para restaurar: sudo make restart-all   (destrói o bucket e recomeça a cadeia do genesis)${N}"
fi
