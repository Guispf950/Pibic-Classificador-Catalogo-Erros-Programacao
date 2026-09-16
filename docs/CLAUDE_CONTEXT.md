# CLAUDE_CONTEXT.md — Classificador de Erros CodeBench (PIBIC/UFAM)

> Documento de handoff. Última atualização: 2026-09-16.
> Autor: Guilherme (guilhermepereira0444@gmail.com)
> Contém decisões de design, estado atual do código e pendências.
>
> **Mudança grande desde a versão de julho/2026:** a classificação deixou de usar o LLM e
> passou a ser 100% determinística; `ferramentas_analise_dinamica.py` foi dividido em módulos por
> responsabilidade; entraram CWE, base de conhecimento (KB) e uma API FastAPI com sandbox Docker;
> a Malha 3 passou de `perf stat` para Callgrind e está desativada por padrão.

---

## 1. O QUE É O PROJETO

Sistema de análise dinâmica automática de código C submetido à plataforma **CodeBench** (juiz
online da UFAM). Protótipo de pesquisa PIBIC que:

1. **Detecta** erros de memória no código do aluno (buffer overflow, use-after-free, double-free,
   valor não inicializado, leaks, null-deref/SIGSEGV) e erros de compilação.
2. **Classifica** o erro de forma **determinística** (sem LLM): mapeia para um **CWE** e um nome
   técnico (`tipo_erro`), e anota o código na linha exata do erro (`// @@`).
3. **Gera feedback formativo** ao aluno com um **LLM local** (Ollama + qwen2.5-coder:7b) — único
   passo que usa IA. O feedback é socrático: guia à correção sem entregá-la.
4. (Exploratório) **Infere a complexidade Big-O** via Callgrind + regressão — Malha 3, desativada.

Duas faces do mesmo pipeline:
- **Catálogo (offline):** `python3 orquestrador.py` varre uma pasta e gera um CSV.
- **API (online):** `api/` expõe o pipeline como serviço FastAPI para o CodeBench.

**Ambiente:** WSL (Ubuntu) dentro do Windows.

---

## 2. ARQUITETURA: PIPELINE DETERMINÍSTICO EM CASCATA

```
Malha 1 (ASan + GDB)        → erros espaciais + crash por sinal (SIGSEGV)
    ↓ erro? → classificação determinística → feedback (LLM) → CSV
    ↓ limpo?
Malha 2 (Valgrind + vgdb)   → não-inicializado + leaks
    ↓ erro? → classificação determinística → feedback (LLM) → CSV
    ↓ limpo?
Malha 3 (Callgrind + regressão Big-O)   → DESATIVADA por padrão (MALHA_3_ATIVA=False)
    ↓ → CSV (sem erro de memória + complexidade inferida)
```

**Princípio de cascata (fail-fast):** a primeira malha que acha erro interrompe o fluxo. A Malha 3
só rodaria em código limpo (medir complexidade de código com Undefined Behavior é sem sentido).

**Princípio de agência local:** o fluxo é determinístico; o LLM não decide nada do diagnóstico —
só interpreta o resultado já apurado para escrever o feedback.

**Anotação inline (FLAME):** em vez de citar "linha 23", o pipeline anota o código com
`// @@ [SINTOMA]/[CAUSA]` na linha exata da ferramenta. Como quem anota é o pipeline (ancorado na
linha real), é determinístico e dispensa o fuzzy matching que o FLAME precisa.

---

## 3. ESTRUTURA DE ARQUIVOS (atual)

```
Classificador de Erros prototipo/
├── orquestrador.py                 ← ponto de entrada (modo catálogo)
├── src/
│   ├── config.py                   ← CONFIGURAÇÃO CENTRAL (todos importam daqui)
│   ├── malha1_asan.py              ← Malha 1 (ASan + GDB)
│   ├── malha2_valgrind.py          ← Malha 2 (Valgrind + vgdb, sync por evento)
│   ├── deteccao_entrada.py         ← gera o stdin (caso de teste .in / heurística)
│   ├── parser_logs.py              ← filtra o log bruto antes do LLM
│   ├── cwe.py                      ← mapeamento determinístico log → CWE + tipo_erro
│   ├── regras_secao.py             ← regras SINTOMA/CAUSA/VAZAMENTO/ORIGEM do log
│   ├── kb.py                       ← recupera doc da KB por chave exata (CWE)
│   └── llm_client.py               ← classificação determinística + anotação + feedback (LLM)
├── base_conhecimento/              ← 1 doc conceitual por CWE (CWE-121, 122, 125, 401, 415,
│                                     416, 457, 476, 562, 590, 762, 787, 825) + TEMPLATE.md
├── api/
│   ├── app.py                      ← FastAPI: /analisar (JSON) e /feedback (SSE)
│   ├── pipeline_adapter.py         ← cola API↔pipeline; modo mock / real
│   ├── sandbox.py                  ← roda a detecção isolada em contêiner Docker
│   ├── runner_analise.py           ← entrypoint dentro do contêiner (Malha 1/2 + limpa log)
│   ├── Dockerfile.analise          ← imagem: Ubuntu + gcc/gdb/valgrind + python3 + src/
│   ├── teste_sse.html              ← página de teste do streaming
│   └── requirements.txt            ← deps do host (fastapi, uvicorn, requests, ...)
├── Trabalhos em Aberto/
│   └── perfilador_desempenho.py    ← Malha 3 (Callgrind + Big-O), exploratória
├── data/submissoes_CE_codebench/   ← submissões dos alunos (.c)
├── experiments/                    ← rodadas versionadas (ver experiments/README.md)
├── docs/                           ← documentação (este arquivo, docx técnico, contexto)
└── output/                         ← saídas transitórias (NÃO versionado)
    ├── catalogo_erros_codebench.csv
    ├── codigos_anotados/<nome>_AnotacaoErro.c
    └── feedbacks/feedback_<nome>.txt
```

**Nota:** o perfilador (Malha 3) fica em `Trabalhos em Aberto/` (fora de `src/`) por ser
exploratório; o orquestrador o carrega de forma protegida via `importlib` — se faltar, o pipeline
de memória segue normalmente.

---

## 4. ESTADO ATUAL DE CADA ARQUIVO

### 4.1 `src/config.py` — configuração central
Concentra todas as constantes. Principais: `URL_LLM_LOCAL` (`http://192.168.0.105:11434/api/generate`),
`NOME_MODELO` (`qwen2.5-coder:7b`), `LLM_TIMEOUT_S=300`, `LLM_KEEP_ALIVE=30m`,
`TEMPERATURA_CLASSIFICACAO=0.0`, `TEMPERATURA_FEEDBACK=0.7`, `MODO_ANOTACAO` (inline/numerica/nenhuma),
`MALHA_3_ATIVA=False`, `VALGRIND_TIMEOUT_S/POLL_S`, e os caminhos (PASTA_CODIGOS, PASTA_FEEDBACKS,
PASTA_KB etc.).

### 4.2 `src/malha1_asan.py` — Malha 1 (ASan + GDB)
`executar_malha_1_asan(caminho, binario_saida, entrada)`. Compila com
`gcc -std=gnu11 -fsanitize=address -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g`.
`ASAN_OPTIONS=abort_on_error=1:detect_leaks=0` (LSan desligado — conflita com o GDB via ptrace).
Roda sob `gdb --batch -ex run -ex "bt full"`. Detecta o relatório do ASan **e** crash por sinal
capturado pelo GDB (`_SINAIS_FATAIS`, para SIGSEGV puro não escapar). Retorna dict com
`tipo` (asan/crash/compilacao) + log, ou None. `-std=gnu11` evita falsos positivos por C23
(false/true/bool viraram keywords).

### 4.3 `src/malha2_valgrind.py` — Malha 2 (Valgrind + vgdb)
`executar_malha_2_valgrind(...)`. Compila com `gcc -std=gnu11 -g` (sem ASan). Flags de origem:
`--track-origins=yes`, `--keep-stacktraces=alloc-and-free`, `--read-var-info=yes`.
**Sincronização por evento** (substituiu o antigo `time.sleep(1.5)`): `_aguardar_evento_valgrind`
retorna `erro_execucao` (congelou num erro; marcador `(action on error) vgdb me`), `terminou`
(lê leak-check) ou `timeout`. O stderr é drenado por uma thread em background.

### 4.4 `src/deteccao_entrada.py` — geração do stdin
Compartilhado por Malha 1 e 2. Prioridade: (1) `<nome>.in`, (2) `_entrada.in` da pasta,
(3) heurística (`scanf("%d", &var)` com a var controlando laço/alocação → `"5\n1 2 3 4 5\n"`),
(4) None (herda o stdin do ambiente). Resolve o hang de programas que leem N.

### 4.5 `src/parser_logs.py` — limpeza do log
`limpar_log_gdb(log_bruto, nome_arquivo)`. Remove ruído (frames da libc, dumps hex, shadow bytes)
e preserva alertas críticos, linhas de localização de memória, acessos READ/WRITE, frames do
arquivo do aluno e variáveis locais do aluno.

### 4.6 `src/cwe.py` — CWE determinístico
`REGRAS_CWE` (regex → CWE, em ordem de prioridade; liberação vem antes de use-after-free por
compartilharem "free'd"). `classificar_cwe(log)` → (id, nome). `classificar_cwe_tipo(log)` →
(id, nome, tipo_erro) via `_TIPO_POR_CWE`. O `tipo_erro` deixou de ser gerado pelo LLM.

### 4.7 `src/regras_secao.py` — seções do log
`REGRAS_SECAO`: (papel, rótulo, regex) para SINTOMA/CAUSA/VAZAMENTO/ORIGEM. É o "contrato" único
com o texto do ASan/Valgrind; base da anotação separada de sintoma e causa.

### 4.8 `src/kb.py` — base de conhecimento
`recuperar_kb(cwe_id)`: lê `base_conhecimento/<CWE-ID>.md` por **chave exata** (evita distrator;
sem embeddings/vector DB). Valida o formato do id (anti path-traversal); retorna "" se não houver
documento (degradação graciosa).

### 4.9 `src/llm_client.py` — o maior arquivo (classificação + anotação + feedback)
Principais métodos:
- `_chamar_llm(prompt, tentativa, temperatura)` — camada única de acesso ao Ollama (streaming,
  format=json, keep_alive).
- `_extrair_pontos_anotacao(log, nome)` — extrai SINTOMA/CAUSA/VAZAMENTO; distingue frame do GDB
  do frame do Valgrind (prioriza o estruturado; fallback GDB p/ SIGSEGV puro).
- `_anotar_codigo(codigo, pontos)` — injeta `// @@` nas linhas exatas.
- `_fim_da_funcao(...)` — fim da função por casamento de chaves (substituiu janela fixa de 40).
- `_refinar_causa_uninit(...)` — move a CAUSA da abertura da função p/ a linha da declaração
  (só quando inequívoco).
- `_evidencia_do_log(log)` — escolhe uma linha real do log p/ `evidencia_log` (anti-alucinação).
- `classificar_erro(...)` — **100% determinístico**; retorna tipo_erro, cwe_id, cwe_nome,
  linha_sintoma, linha_causa, evidencia_log, codigo_anotado.
- `montar_prompt_feedback(...)` — fonte única das regras pedagógicas (JSON e texto); recupera KB,
  aplica ablação (MODO_ANOTACAO), prompt socrático anti-vazamento com exemplos "não copiar".
- `gerar_feedback(...)` / `gerar_feedback_stream(...)` — 2ª etapa (LLM). JSON com retry/backoff
  (catálogo) e gerador token-a-token (SSE da API). Temperatura 0.7.

### 4.10 `orquestrador.py` — ponto de entrada (catálogo)
Itera os `.c`, roda a cascata, limpa o log, chama `classificar_erro` e (mesmo laço, em memória)
`gerar_feedback`. Salva CSV (15 colunas: Arquivo, Ferramenta, Tipo Erro, CWE ID, CWE Nome,
Linha Sintoma, Linha Causa, Evidencia Log, Feedback, Complexidade, ...), código anotado e feedback
`.txt`. Distingue erro de memória de erro de compilação.

### 4.11 API (`api/`)
- `app.py` — endpoints `/analisar` (JSON), `/feedback` (SSE com eventos status/diagnostico/token/
  fim), variantes `_arquivo` (upload), `/saude`, `/teste`. `_sem_internos()` remove `codigo_anotado`
  antes de responder (não vaza a localização exata ao aluno).
- `pipeline_adapter.py` — `analisar()` e `stream_feedback()`; modo mock (padrão) ou real
  (`USAR_PIPELINE_REAL=1`). No real: detecção no sandbox + classificação/feedback no host.
- `sandbox.py` — `rodar_em_sandbox(...)`: `docker run` com `--network none`, `--read-only` +
  `--tmpfs /tmp`, `--memory 512m`, `--cpus 1`, `--pids-limit 128`, `--user 1000:1000`,
  `--cap-add SYS_PTRACE`, `seccomp=unconfined`. Timeout e modo mock (`MODO_SANDBOX != docker`).
- `runner_analise.py` — roda dentro do contêiner: Malha 1/2 + `limpar_log_gdb`, emite JSON após
  `===RESULTADO_JSON===`. Lê entrada autoritativa de `/work/entrada.in`.
- `Dockerfile.analise` — Ubuntu 22.04 + gcc/gdb/valgrind/libasan8/libc6-dev/python3; copia `src/`
  e o runner. **Build a partir da raiz** (`docker build -f api/Dockerfile.analise -t analise-mem:latest .`).

### 4.12 `Trabalhos em Aberto/perfilador_desempenho.py` — Malha 3 (exploratória)
Callgrind (`callgrind_annotate`, `--threshold=100`) para contar instruções (Ir) só do binário do
aluno (isola o algoritmo do I/O da libc); fallback de tempo de parede (mediana). Regressão
`curve_fit` sobre O(1)...O(2^N), escolhe maior R². Cenário A (escalável) vs. B (entrada fixa → N/A).
Desativada por padrão; precisa de fundamentação teórica para entrar oficialmente.

---

## 5. DECISÕES DE DESIGN (com justificativas)

| Decisão | Razão |
|---|---|
| Classificação 100% determinística (sem LLM) | Diagnóstico rápido, estável e auditável; evita alucinação de modelo 7B |
| CWE + tipo_erro por regex (cwe.py) | Padrão citável (MITRE/Juliet); checagem de consistência do diagnóstico |
| LLM só no feedback | O modelo interpreta, não decide — agência local |
| Duas temperaturas (0.0 / 0.7) | Classificação determinística; feedback mais natural |
| Anotação inline `// @@` (FLAME) | Anotar no código supera citar nº de linha (baixa "compreensão numérica" da LLM) |
| KB por chave exata (CWE), sem embeddings | Elimina o distrator por construção; sem vector DB; auditável |
| Malha 1 com `detect_leaks=0` | LSan conflita com o GDB via ptrace; leaks vão para o Valgrind |
| Malha 2 com sync por evento | `sleep` fixo entra em corrida com o startup do Valgrind |
| Detecção isolada em Docker; LLM no host | Código do aluno é não confiável; contêiner sem rede não alcança o Ollama |
| Malha 3 com Callgrind (não `perf`) | `perf` depende de PMU (indisponível em WSL); Callgrind conta por emulação e por objeto |
| `-std=gnu11` nas compilações | Alinha ao CodeBench; evita falsos positivos por C23 (false/true/bool keywords) |
| Perfilador separado, fora de src/ | Exploratório; carregado via importlib, não quebra o pipeline se faltar |

---

## 6. DOIS CENÁRIOS DE EXERCÍCIO (para a Malha 3)

**Cenário A — escalável** (`scanf("%d", &n)` com `n` controlando laço/alocação): a Malha 3 injeta N
crescente, mede e infere Big-O.

**Cenário B — entrada fixa** (ex.: `scanf("%d %d %d", ...)`): retorna
`{"status": "nao_aplicavel", "complexidade_inferida": "N/A — Exercício de Entrada Fixa"}`.
(No caminho da API, a entrada vem sempre autoritativa na requisição — a heurística não é usada.)

---

## 7. FLUXO DA ENTRADA (caso de teste)

- **Catálogo:** `deteccao_entrada` procura `.in`/`_entrada.in`; sem isso, heurística; sem isso, None.
- **API:** a `entrada` da requisição é **autoritativa** — `sandbox.py` grava em `entrada.in`, o
  `runner_analise.py` lê de `/work/entrada.in` e repassa às malhas (mesmo vazia). A heurística não
  é usada nesse caminho.

---

## 8. PENDÊNCIAS / PRÓXIMAS FASES

- **Transporte do stream até o aluno:** como o SSE chega ao front do CodeBench (SSE repassado?
  WebSocket? polling?) — confirmar com a equipe do CodeBench.
- **Filtro determinístico anti-vazamento:** complementar às regras do prompt, robusto a conjugações
  verbais (o regex atual subconta "adicionar"/"adicionasse"/"verifique" etc.), como etapa
  pós-geração. A proibição já vive no prompt (Regra 1).
- **Feedback para erro de compilação:** hoje há placeholder; decidir se gera feedback próprio.
- **Malha 3:** fundamentação teórica para compor oficialmente o pipeline; hoje desativada.
- **Parser:** avaliar RIN (representação intermediária normalizada) e saída XML do Valgrind.

---

## 9. CONFIGURAÇÃO DO AMBIENTE

```
LLM local:   Ollama em http://192.168.0.105:11434  (ver URL_LLM_LOCAL em src/config.py)
Modelo:      qwen2.5-coder:7b
Runtime:     Python 3 (WSL Ubuntu)
Deps host:   requests, numpy, scipy  (+ fastapi, uvicorn para a API — api/requirements.txt)
Ferramentas: gcc, gdb, valgrind (Callgrind); Docker (só no modo real da API)
```

Testar o Ollama a partir do host: `curl http://192.168.0.105:11434/api/tags`.

---

## 10. COMO RODAR

**Catálogo:**
```bash
python3 orquestrador.py
# saídas em output/: catalogo_erros_codebench.csv, codigos_anotados/, feedbacks/
```

**Ablação (sem editar código):**
```bash
ANOTACAO_MODO=inline   python3 orquestrador.py   # padrão
ANOTACAO_MODO=numerica python3 orquestrador.py
ANOTACAO_MODO=nenhuma  python3 orquestrador.py
```

**API — modo mock** (de dentro de `api/`): `uvicorn app:app --reload`
**API — modo real** (da raiz):
```bash
docker build -f api/Dockerfile.analise -t analise-mem:latest .
USAR_PIPELINE_REAL=1 MODO_SANDBOX=docker uvicorn api.app:app --reload
```

---

## 11. DOCUMENTAÇÃO RELACIONADA

- `README.md` (raiz) — visão geral do pipeline + API.
- `api/README.md` — guia completo da API (mock, build, real, testes, variáveis, troubleshooting).
- `docs/Documentacao_Tecnica_Pipeline.docx` — detalhamento aprofundado arquivo por arquivo.
- `experiments/README.md` — convenção de registro das rodadas de experimento.
- `Catalogo_Pipeline_Dinamico.csv` (raiz) — catálogo do que o pipeline detecta (ferramenta × CWE).

---

## 12. NOTA OPERACIONAL (WSL + VS Code)

O VS Code costuma sobrescrever o arquivo no disco a partir do buffer aberto no editor. Antes de
commit/push, **fechar ou dar "Revert File"** nos arquivos editados fora do editor, para não perder
alterações. Versionamento: desenvolvimento na `main`, **tags** para congelar versões (não branches
paralelas de longa vida); `output/` é ignorado pelo git, resultados que embasam conclusões vão para
`experiments/`.
