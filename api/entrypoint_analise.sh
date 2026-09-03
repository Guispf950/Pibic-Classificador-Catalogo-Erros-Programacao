#!/bin/sh
# OBSOLETO — substituído por runner_analise.py.
# =============================================
# Este script era o entrypoint da 1ª versão (só ASan, em shell). A imagem agora
# usa `python3 /app/runner_analise.py`, que reaproveita as SUAS malhas (ASan+GDB e
# Valgrind) para ter paridade total com o orquestrador. Pode ignorar/remover este
# arquivo — ele não é mais referenciado pelo Dockerfile.analise.
echo "entrypoint_analise.sh esta obsoleto; use runner_analise.py (ver Dockerfile.analise)." >&2
exit 1
