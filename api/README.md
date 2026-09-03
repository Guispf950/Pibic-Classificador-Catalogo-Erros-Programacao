# Serviço FastAPI — análise e feedback

Serviço que expõe o pipeline como uma **API separada**, chamada pelo CodeBench.
Dois endpoints: `/analisar` (JSON) e `/feedback` (streaming SSE).

## Arquitetura (modo real)

```
                 HOST (a API)                         CONTÊINER (descartável, --network none)
  ┌───────────────────────────────────┐          ┌──────────────────────────────────────┐
  │ POST /analisar                     │          │ runner_analise.py                    │
  │   pipeline_adapter.analisar()      │  docker  │   Malha 1 (ASan+GDB)                 │
  │     └─ sandbox.rodar_em_sandbox() ─┼──run────▶│   Malha 2 (Valgrind)  → log do erro  │
  │     └─ src.llm_client.classificar  │◀─JSON────┤   limpar_log_gdb()                   │
  │        _erro()   (Ollama, no host) │          └──────────────────────────────────────┘
  │ POST /feedback                     │
  │   gerar_feedback_stream() (Ollama) │   A DETECÇÃO (código não confiável) roda isolada.
  └───────────────────────────────────┘   O LLM roda no HOST (o contêiner não tem rede).
```

## Arquivos

| Arquivo | Papel |
|---|---|
| `app.py` | A API FastAPI: os dois endpoints e o formato SSE. |
| `pipeline_adapter.py` | Cola entre a API e o pipeline. Modo **mock** (padrão) ou **real**. |
| `sandbox.py` | Wrapper que roda a **detecção** isolada em um contêiner Docker. |
| `runner_analise.py` | Roda DENTRO do contêiner: chama Malha 1/2 + limpa o log, emite JSON. |
| `Dockerfile.analise` | "Molde" (imagem): Ubuntu + gcc + gdb + valgrind + python3 + cópia de `src/`. |
| `teste_sse.html` | Página para testar o streaming no navegador. |
| `requirements.txt` | Dependências Python (do host). |

## 1) Rodar em modo MOCK (testável já, sem Ollama/Docker)

De dentro de `api/`:
```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```
- Doc automática: http://127.0.0.1:8000/docs
- Página de teste do SSE: http://127.0.0.1:8000/teste
- `/saude` deve retornar `{"ok": true, "pipeline_real": false}`.

## 2) Ligar o pipeline REAL

### 2.1 Construir a imagem de análise (uma vez)
O build copia `src/`, então rode **a partir da RAIZ do projeto** (a pasta-mãe de `api/`):
```
cd ..                                   # raiz do projeto (onde está src/)
docker build -f api/Dockerfile.analise -t analise-mem:latest .
```

### 2.2 Subir a API em modo real (a partir da RAIZ do projeto)
Rodar da raiz é importante: é de lá que `./base_conhecimento` (a KB) resolve.
```
USAR_PIPELINE_REAL=1 MODO_SANDBOX=docker IMAGEM_ANALISE=analise-mem:latest \
  uvicorn api.app:app --reload
```
- `/saude` deve retornar `{"ok": true, "pipeline_real": true}`.
- O Ollama precisa estar acessível pelo HOST no endereço de `src/config.py`
  (`URL_LLM_LOCAL`). Teste antes: `curl http://192.168.0.105:11434/api/tags`.

## Testar

`/analisar` (POST JSON) — Insomnia/Postman/curl:
```
curl -X POST http://127.0.0.1:8000/analisar \
  -H "Content-Type: application/json" \
  -d '{"codigo":"int main(){int *p=0;return *p;}","entrada":"","nome_arquivo":"submissao.c"}'
```

`/feedback` (SSE) — use `curl -N` (o `-N` mostra os tokens chegando), ou a página `/teste`:
```
curl -N -X POST http://127.0.0.1:8000/feedback \
  -H "Content-Type: application/json" \
  -d '{"codigo":"...","entrada":"","nome_arquivo":"submissao.c"}'
```

## Variáveis de ambiente

| Variável | Padrão | Efeito |
|---|---|---|
| `USAR_PIPELINE_REAL` | `0` | `1` liga o pipeline real (sandbox + LLM) em vez do mock. |
| `MODO_SANDBOX` | `mock` | `docker` roda a detecção no contêiner isolado. |
| `IMAGEM_ANALISE` | `analise-mem:latest` | Nome da imagem Docker usada pelo sandbox. |
| `SANDBOX_TIMEOUT_S` | `180` | Teto de tempo por execução (heurística de 3 min). |
| `ANOTACAO_MODO` | `inline` | Variável de ablação (inline / numerica / nenhuma), lida por `src/config.py`. |

## Solução de problemas (modo real)

- **`docker: command not found`** — instale o Docker no WSL (Docker Desktop com
  integração WSL2, ou `docker.io` no Ubuntu) e confirme com `docker run hello-world`.
- **ASan aborta com "Shadow memory range interleaves..."** — é o ASLR do host novo.
  Já subimos o contêiner com `--security-opt seccomp=unconfined`; se persistir, no host:
  `sudo sysctl -w vm.mmap_rnd_bits=28` (ou 30) e rode de novo.
- **GDB/Valgrind falham com "ptrace operation not permitted"** — o contêiner já pede
  `--cap-add SYS_PTRACE`; confirme que sua versão do Docker respeita a flag.
- **`/feedback` não streama** — teste o Ollama a partir do host (`curl .../api/tags`).
  Se estiver noutra máquina da LAN, ajuste `URL_LLM_LOCAL` em `src/config.py`.
- **Erro de import `src...`** — rode a API real **da raiz** (`uvicorn api.app:app`), não de `api/`.

## Entrada (caso de teste) — como funciona

A `entrada` enviada na requisição (`/analisar` e `/feedback`) é **autoritativa**: o
`sandbox.py` a grava em `entrada.in` no diretório montado, o `runner_analise.py` a lê de
`/work/entrada.in` e a repassa às malhas como stdin (mesmo vazia). A heurística antiga de
adivinhar o stdin **não é usada** no caminho da API — a entrada vem sempre com o código.
(No uso offline, sem `entrada`, as malhas ainda caem na detecção por `.in`/heurística.)

## Diagnóstico rápido vs. feedback detalhado

- `/analisar` -> **100% determinístico** (sem LLM): `tipo_erro`, `cwe_id`, `cwe_nome`,
  `linha_sintoma`, `linha_causa`, `evidencia_log`, `codigo_anotado`. Resposta imediata.
- `/feedback` -> roda o mesmo diagnóstico determinístico e, **em seguida**, o passo com
  LLM (streaming) para o feedback socrático. É o que o aluno pede quando quer mais detalhe.

## Pendência a confirmar (não assumida)

**Transporte até o aluno.** Como o stream chega ao navegador do aluno depende de como o
**front do CodeBench** recebe tempo real (SSE repassado? WebSocket? polling?). Confirmar
com a equipe do CodeBench.
