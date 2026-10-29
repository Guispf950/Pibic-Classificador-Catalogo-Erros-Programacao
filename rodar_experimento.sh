#!/usr/bin/env bash
# rodar_experimento.sh — roda uma rodada de avaliação (Juliet ou CodeBench) no contêiner seguro.
#
# Uso (Git Bash, na raiz do projeto):
#   ./rodar_experimento.sh juliet    --total 50 --seed 42
#   ./rodar_experimento.sh juliet    --cwes 121,416 --por-grupo 5 --todos-erros
#   ./rodar_experimento.sh codebench --total 30 --veredito WA,RE --seed 42
#   ./rodar_experimento.sh codebench --por-grupo 1 --veredito RE --todos-erros
# Tudo depois do nome do dataset vai direto para avaliar_juliet.py / avaliar_codebench.py
# (parâmetros comuns: --total, --por-grupo, --seed, --todos-erros; ver experimentos.py).
#
# O que o script faz por você:
#   1. lê o dataset no WSL (~/datasets) e o envia ao contêiner por um "tar" (o Docker Desktop não
#      consegue montar pastas do WSL enquanto a integração com o WSL estiver desligada);
#   2. roda o código SEMPRE no contêiner, sem rede, sem root e com limites de memória/processos;
#   3. registra no histórico o commit exato do código (com "+alterações" se houver mudança não
#      commitada), que o contêiner não consegue calcular sozinho (não tem git).
# Os CSVs saem em ./output, como numa execução direta.
set -euo pipefail

dataset="${1:-}"
case "$dataset" in
  juliet)    pasta="juliet";     script="avaliar_juliet.py";    dir_flag="--juliet-dir";    dir_dado="juliet/C" ;;
  codebench) pasta="cb-dataset"; script="avaliar_codebench.py"; dir_flag="--codebench-dir"; dir_dado="cb-dataset" ;;
  *) echo "Uso: $0 juliet|codebench [parâmetros do avaliador]"; exit 1 ;;
esac
shift

raiz="$(cd "$(dirname "$0")" && pwd)"
cd "$raiz"
commit="$(git rev-parse --short HEAD)"
if [ -n "$(git status --porcelain src avaliar_juliet.py avaliar_codebench.py experimentos.py)" ]; then
  commit="$commit+alterações"
fi
imagem="${IMAGEM_ANALISE:-analise-mem:latest}"
echo "[rodar_experimento] dataset=$dataset | código=$commit | imagem=$imagem | args: $*"

# Os argumentos do usuário viajam como variável de ambiente (evita problemas de aspas no bash -c).
wsl.exe -e bash -lc "tar -C ~/datasets -cf - '$pasta'" |
MSYS_NO_PATHCONV=1 docker run -i --rm \
  --network none --memory 4g --cpus 2 --pids-limit 256 \
  --tmpfs /tmp:size=1g,exec --user 1000:1000 \
  --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
  -e "COMMIT_CODIGO=$commit" -e "ARGS_AVALIADOR=$*" \
  -v "$raiz:/repo" -w /repo --entrypoint bash "$imagem" -c "
    set -e
    mkdir -p /home/sandbox/dados /tmp/stub
    tar -xf - -C /home/sandbox/dados
    touch /tmp/stub/requests.py   # o llm_client importa requests; o avaliador não chama o LLM
    PYTHONPATH=/tmp/stub python3 -u $script $dir_flag /home/sandbox/dados/$dir_dado \$ARGS_AVALIADOR
  "
