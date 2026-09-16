# Classificador de Erros — Pipeline de Análise Dinâmica (PIBIC / UFAM)

Pipeline **determinístico** que analisa código C submetido ao juiz **CodeBench**, detecta
erros de memória em tempo de execução, **classifica-os sem depender de IA** e usa um **LLM
local** apenas para escrever um **feedback formativo (socrático)** ao aluno sem entregar a
solução pronta.

A ideia central é a **agência local**: o fluxo é controlado por regras determinísticas
(ferramentas de análise + tabelas de mapeamento); o LLM não decide nada do diagnóstico, ele só
*interpreta* o resultado para conversar com o aluno. Isso torna o diagnóstico rápido, estável e
auditável, e reduz a chance de alucinação de um modelo pequeno (7B).

## O que ele detecta

Erros de memória em C capturados por instrumentação dinâmica: *buffer overflow* (heap/stack),
*use-after-free*, *double-free*/*free* inválido, uso de valor **não inicializado**, *memory
leak*, *null-pointer dereference* (SIGSEGV) e erros de compilação. Cada erro é mapeado para um
**CWE** (Common Weakness Enumeration, do MITRE) — o padrão citável que identifica a fraqueza.

## Arquitetura em cascata (fail-fast)

O código do aluno passa por malhas em sequência; a **primeira** que encontra um erro
interrompe o fluxo (fail-fast):

- **Malha 1 — AddressSanitizer + GDB** (`src/malha1_asan.py`): erros espaciais de acesso
  (overflows, use-after-free) e crashes por sinal (SIGSEGV etc.), capturados pelo GDB.
- **Malha 2 — Valgrind (Memcheck) + vgdb** (`src/malha2_valgrind.py`): só roda se a Malha 1
  passou limpa. Pega valores não inicializados e *memory leaks*, com o GDB conectado ao vivo
  (vgdb) no ponto exato do erro.
- **Malha 3 — Perfilador de complexidade** (`Trabalhos em Aberto/`): exploratória, **desativada
  por padrão** (`MALHA_3_ATIVA=False`). Infere Big-O por regressão sobre entradas escalonadas.

> Leaks são deliberadamente entregues à Malha 2: na Malha 1 o LeakSanitizer é desligado
> (`detect_leaks=0`), pois entra em conflito de `ptrace` com o GDB e produziria um log mais
> pobre que o do Valgrind+vgdb.

## Fluxo de informação (modo catálogo, via `orquestrador.py`)

```
  código.c
     │
     ▼
 [Malha 1: ASan+GDB] ──erro?──► log bruto
     │ (limpo)                     │
     ▼                             │
 [Malha 2: Valgrind+vgdb] ─erro?─► log bruto
     │ (limpo)                     │
     ▼                             ▼
 [Malha 3 / passou limpo]   [parser_logs.limpar_log_gdb]  ← filtra ruído (libc, dumps)
                                   │
                                   ▼
                     [llm_client.classificar_erro]  ← 100% DETERMINÍSTICO (sem LLM)
                        │  usa: cwe.py (CWE + tipo_erro)
                        │       regras_secao.py (SINTOMA/CAUSA/VAZAMENTO)
                        │  produz: linhas do erro + código anotado (// @@)
                        ▼
                     [llm_client.gerar_feedback]   ← ÚNICO passo com LLM (Ollama)
                        │  recupera doc da KB por CWE (kb.py)
                        │  monta prompt socrático anti-vazamento
                        ▼
              CSV (catálogo) + código anotado + feedback .txt
```

O **diagnóstico** (tipo do erro, CWE, linha do sintoma, linha da causa, evidência do log) sai
inteiro das ferramentas. O **LLM entra só no fim**, para transformar esse diagnóstico em um
texto que leva o aluno a descobrir a correção sozinho.

### Anotação inline (`// @@`) — inspirada no FLAME

Em vez de dizer ao modelo "o erro está na linha 23", o pipeline **anota o próprio código** com
um comentário `// @@ [SINTOMA]/[CAUSA]` na linha exata reportada pela ferramenta. O artigo FLAME
mostra que anotar no código supera de longe passar o número da linha em texto (LLMs têm baixa
"compreensão numérica"). Como quem anota é o pipeline — ancorado na linha exata da ferramenta —
a marcação é determinística e dispensa o *fuzzy matching* que o FLAME precisa.

## Duas faces: catálogo (offline) e API (online)

- **Catálogo** (`orquestrador.py`): varre uma pasta de submissões e gera um CSV com o
  diagnóstico + feedback de cada uma. É o modo de pesquisa/avaliação em lote.
- **API** (`api/`): expõe o mesmo pipeline como serviço FastAPI para o CodeBench, com a
  **detecção isolada em contêiner Docker** (código não confiável) e o **LLM rodando no host**.
  Dois endpoints: `/analisar` (JSON, diagnóstico imediato) e `/feedback` (streaming SSE, o
  feedback "sendo digitado"). Ver `api/README.md`.

## Estrutura do repositório

| Caminho | Papel |
|---|---|
| `orquestrador.py` | Ponto de entrada do modo catálogo: roda a cascata e gera o CSV. |
| `src/config.py` | **Configuração central**: caminhos, parâmetros do LLM, temperaturas, modo de anotação, flags das malhas. |
| `src/malha1_asan.py` | Malha 1 (ASan + GDB). |
| `src/malha2_valgrind.py` | Malha 2 (Valgrind + vgdb), com sincronização por evento. |
| `src/parser_logs.py` | Filtra o log bruto (remove ruído da libc/dumps) antes do LLM. |
| `src/deteccao_entrada.py` | Descobre/gera o stdin que exercita o código (caso de teste `.in` ou heurística). |
| `src/cwe.py` | Mapeamento determinístico log → CWE + nome técnico do erro (`tipo_erro`). |
| `src/regras_secao.py` | Regras que identificam as seções do relatório (SINTOMA/CAUSA/VAZAMENTO/ORIGEM). |
| `src/kb.py` | Base de conhecimento: recupera o documento do CWE por chave exata. |
| `src/llm_client.py` | Classificação determinística + anotação inline + geração de feedback (Ollama). |
| `base_conhecimento/` | Um documento conceitual por CWE (material de apoio para o feedback). |
| `api/` | Serviço FastAPI + sandbox Docker (ver `api/README.md`). |
| `Trabalhos em Aberto/` | Módulos exploratórios (perfilador de complexidade / Malha 3). |
| `data/` | Submissões dos alunos (dados de entrada). |
| `experiments/` | Rodadas de experimento — **versionadas** (ver `experiments/README.md`). |
| `docs/` | Documentação (fundamentação, contexto, detalhamento dos arquivos). |
| `output/` | Saídas transitórias de uma rodada — **não versionado** (ver `.gitignore`). |

## Como rodar (modo catálogo)

```bash
python orquestrador.py
```

O catálogo sai em `output/catalogo_erros_codebench.csv`; os códigos anotados em
`output/codigos_anotados/<nome>_AnotacaoErro.c`; e um feedback por submissão em
`output/feedbacks/feedback_<nome>.txt`.

**Requisitos:** `gcc`, `valgrind`, `gdb`; Python 3 (`requests`, `numpy`, `scipy`); Ollama local
servindo `qwen2.5-coder:7b` no endereço configurado em `src/config.py` (`URL_LLM_LOCAL`).

## Como rodar (API)

Instruções completas (modo mock, build da imagem, modo real, testes, variáveis de ambiente e
solução de problemas) em **`api/README.md`**. Resumo:

```bash
# modo mock (sem Ollama/Docker), de dentro de api/
uvicorn app:app --reload

# modo real, a partir da RAIZ do projeto
docker build -f api/Dockerfile.analise -t analise-mem:latest .
USAR_PIPELINE_REAL=1 MODO_SANDBOX=docker uvicorn api.app:app --reload
```

## Experimentos de anotação (ablação estilo FLAME)

A forma como a localização do erro chega ao LLM é controlada pela variável `ANOTACAO_MODO` —
trocar de condição **não exige editar código**:

```bash
ANOTACAO_MODO=inline   python orquestrador.py   # código anotado com // @@   (padrão)
ANOTACAO_MODO=numerica python orquestrador.py   # código original + linhas em texto (FLAME_num)
ANOTACAO_MODO=nenhuma  python orquestrador.py   # baseline: código original, sem dica de linha
```

Só isso muda entre as condições — o resto do pipeline é idêntico, para a comparação isolar
exatamente essa variável. Convenção de registro em `experiments/README.md`.

## Parâmetros principais (`src/config.py`)

| Constante | Padrão | Efeito |
|---|---|---|
| `URL_LLM_LOCAL` | `http://192.168.0.105:11434/api/generate` | Endereço do Ollama. |
| `NOME_MODELO` | `qwen2.5-coder:7b` | Modelo local usado. |
| `TEMPERATURA_CLASSIFICACAO` | `0.0` | Determinística (a classificação não usa mais o LLM). |
| `TEMPERATURA_FEEDBACK` | `0.7` | Texto mais natural no feedback. |
| `MODO_ANOTACAO` | `inline` | Variável de ablação (`inline`/`numerica`/`nenhuma`). |
| `MALHA_3_ATIVA` | `False` | Liga/desliga o perfilador de complexidade. |

## Versionamento

- Desenvolvimento na `main`; **tags** para congelar versões reproduzíveis
  (`git tag -a inline-v1 -m "..."`), não branches paralelas de longa vida.
- Resultados que embasam conclusões ficam em `experiments/`; saídas transitórias (`output/`)
  são ignoradas pelo git.
