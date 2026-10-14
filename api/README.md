# Serviço FastAPI — análise e feedback

Serviço que expõe o pipeline como uma **API separada**, chamada pelo CodeBench. Segue convenções
REST: recursos no plural, versão no caminho (`/v1`) e a ação expressa pelo método HTTP.

## Endpoints

| Método + caminho | Papel |
|---|---|
| `POST /v1/diagnostics` | Diagnóstico determinístico do erro (JSON). Aceita o código em **JSON** ou como **arquivo** (multipart). |
| `POST /v1/feedbacks` | Gera o feedback ao aluno em **streaming (SSE)**, **persiste** o resultado e devolve **201** com o `id` no header `Location`. Mesmos dois formatos de entrada. |
| `GET /v1/feedbacks` | Lista os feedbacks persistidos (resumo) — base para avaliação posterior. |
| `GET /v1/feedbacks/{id}` | Recupera um feedback persistido (**404** se não existir). |
| `GET /v1/health` | Checagem de saúde do serviço. |
| `GET /teste` | Página HTML de teste do streaming (uso em demonstrações). |

> **Um endpoint por recurso, dois formatos de entrada.** `/v1/diagnostics` e `/v1/feedbacks`
> aceitam tanto `application/json` (`{codigo, entrada, nome_arquivo}`) quanto
> `multipart/form-data` (campos `codigo` e `entrada`) — o servidor decide pelo `Content-Type`.
> Não há mais endpoints separados por formato. **`codigo` e `entrada` são obrigatórios**: a
> `entrada` é o caso de teste que exercita a análise dinâmica (só pode ser vazia se o programa
> não lê stdin). Campo obrigatório ausente → `422`.

## Arquitetura (modo real)

```
                 HOST (a API)                         CONTÊINER (descartável, --network none)
  ┌───────────────────────────────────┐          ┌──────────────────────────────────────┐
  │ POST /v1/diagnostics               │          │ runner_analise.py                    │
  │   pipeline_adapter.analisar()      │  docker  │   Malha 1 (ASan+GDB)                 │
  │     └─ sandbox.rodar_em_sandbox() ─┼──run────▶│   Malha 2 (Valgrind)  → log do erro  │
  │     └─ src.llm_client.classificar  │◀─JSON────┤   limpar_log_gdb()                   │
  │        _erro()   (Ollama, no host) │          └──────────────────────────────────────┘
  │ POST /v1/feedbacks                 │
  │   gerar_feedback_stream() (Ollama) │   A DETECÇÃO (código não confiável) roda isolada.
  │   + feedback_store.salvar()        │   O LLM roda no HOST (o contêiner não tem rede).
  └───────────────────────────────────┘
```

## Arquivos

| Arquivo | Papel |
|---|---|
| `app.py` | A API FastAPI: os endpoints REST e o formato SSE. |
| `pipeline_adapter.py` | Cola entre a API e o pipeline. Modo **mock** (padrão) ou **real**. |
| `feedback_store.py` | Persistência dos feedbacks gerados (JSON por feedback, em `output/feedbacks_api/`). |
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
- `/v1/health` deve retornar `{"ok": true, "pipeline_real": false}`.

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
- `/v1/health` deve retornar `{"ok": true, "pipeline_real": true}`.
- O Ollama precisa estar acessível pelo HOST no endereço de `src/config.py`
  (`URL_LLM_LOCAL`). Teste antes: `curl http://192.168.0.105:11434/api/tags`.

## Testar

`POST /v1/diagnostics` (JSON) — Insomnia/Postman/curl:
```
curl -X POST http://127.0.0.1:8000/v1/diagnostics \
  -H "Content-Type: application/json" \
  -d '{"codigo":"int main(){int *p=0;return *p;}","entrada":"","nome_arquivo":"submissao.c"}'
```

`POST /v1/diagnostics` (multipart — o MESMO endpoint, enviando arquivos):
```
curl -X POST http://127.0.0.1:8000/v1/diagnostics \
  -F "codigo=@submissao.c" -F "entrada=@submissao.in"
```

`POST /v1/feedbacks` (SSE) — use `curl -N` (mostra os tokens chegando), ou a página `/teste`:
```
curl -N -X POST http://127.0.0.1:8000/v1/feedbacks \
  -H "Content-Type: application/json" \
  -d '{"codigo":"...","entrada":"","nome_arquivo":"submissao.c"}'
```

Recuperar os feedbacks persistidos (para avaliação posterior):
```
curl http://127.0.0.1:8000/v1/feedbacks            # lista (resumo)
curl http://127.0.0.1:8000/v1/feedbacks/<id>       # um feedback completo
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

A `entrada` enviada na requisição (`/v1/diagnostics` e `/v1/feedbacks`) é **autoritativa**: o
`sandbox.py` a grava em `entrada.in` no diretório montado, o `runner_analise.py` a lê de
`/work/entrada.in` e a repassa às malhas como stdin (mesmo vazia). A heurística antiga de
adivinhar o stdin **não é usada** no caminho da API — a entrada vem sempre com o código.
(No uso offline, sem `entrada`, as malhas ainda caem na detecção por `.in`/heurística.)

## Diagnóstico rápido vs. feedback detalhado

- `POST /v1/diagnostics` -> **100% determinístico** (sem LLM): `tipo_erro`, `cwe_id`, `cwe_nome`,
  `linha_sintoma`, `linha_causa`, `evidencia_log`. Resposta imediata. (O `codigo_anotado` é
  interno e **não** é devolvido ao cliente, para não vazar a localização exata do erro.)
- `POST /v1/feedbacks` -> roda o mesmo diagnóstico determinístico e, **em seguida**, o passo com
  LLM (streaming) para o feedback socrático, persistindo o resultado.

## Persistência dos feedbacks

Cada feedback gerado por `POST /v1/feedbacks` é salvo como um JSON em `output/feedbacks_api/`,
com o diagnóstico (CWE, tipo, linhas), o código, o texto completo, o modelo e o modo de anotação.
O objetivo é permitir a **avaliação posterior da qualidade pedagógica**. O `id` volta no header
`Location` da resposta e nos eventos SSE; a coleção é navegável por `GET /v1/feedbacks`.

## Códigos de status

- `200` — diagnóstico devolvido; `GET` de feedback bem-sucedido.
- `201` — feedback criado (POST /v1/feedbacks), com `Location: /v1/feedbacks/{id}`.
- `404` — feedback inexistente em `GET /v1/feedbacks/{id}`.
- `415` — `Content-Type` não suportado (use JSON ou multipart).
- `422` — corpo inválido (validação do Pydantic).
- `503` — dependência de análise indisponível (Docker/runner). Um **erro no código do aluno**
  não é erro de API: retorna `200`/`201` com o erro descrito no corpo/stream.

## Pendência a confirmar (não assumida)

**Transporte até o aluno.** Como o stream chega ao navegador do aluno depende de como o
**front do CodeBench** recebe tempo real (SSE repassado? WebSocket? polling?). Confirmar
com a equipe do CodeBench.
