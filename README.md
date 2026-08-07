# Classificador de Erros — Pipeline de Análise Dinâmica (PIBIC / UFAM)

Pipeline determinístico que analisa código C submetido ao juiz **CodeBench**, detecta erros
de memória em tempo de execução (AddressSanitizer / Valgrind), **anota o erro no próprio
código** e usa um **LLM local** para classificá-lo (tipo, causa, feedback ao aluno).

## Estrutura do repositório

| Caminho | Papel |
|---|---|
| `orquestrador.py` | Ponto de entrada: roda a cascata (Malha 1 → 2 → 3) e gera o catálogo. |
| `src/` | O pipeline: malhas (`malha1_asan`, `malha2_valgrind`), `parser_logs`, `deteccao_entrada`, `llm_client`, `regras_secao`. |
| `src/config.py` | **Configuração central**: caminhos, chaves do LLM, temperatura, modo de anotação e flags das malhas. |
| `Trabalhos em Aberto/` | Módulos exploratórios (perfilador de complexidade / Malha 3). |
| `data/` | Submissões dos alunos (dados). |
| `experiments/` | Rodadas de experimento — **versionadas** (ver `experiments/README.md`). |
| `docs/` | Documentação (fundamentação, contexto). |
| `output/` | Saídas transitórias de uma rodada — **NÃO versionado** (ver `.gitignore`). |

## Como rodar

```bash
python orquestrador.py
```

O catálogo sai em `output/catalogo_erros_codebench.csv` e os códigos anotados em
`output/codigos_anotados/<nome>_AnotacaoErro.c`.

**Requisitos:** `gcc`, `valgrind`, `gdb`; Python 3 (`requests`, `numpy`, `scipy`);
Ollama local servindo `qwen2.5-coder:7b`.

## Experimentos de anotação (ablação estilo FLAME)

A representação da localização do erro entregue ao LLM é controlada pela variável de
ambiente `ANOTACAO_MODO` — trocar de condição **não exige editar código**:

```bash
ANOTACAO_MODO=inline   python orquestrador.py   # código anotado com // @@   (padrão)
ANOTACAO_MODO=numerica python orquestrador.py   # código original + linhas em texto (FLAME_num)
ANOTACAO_MODO=nenhuma  python orquestrador.py   # baseline: código original, sem dica de linha
```

Só isso muda entre as condições — o resto do pipeline é idêntico, para a comparação isolar
exatamente essa variável. Detalhes e convenção de registro em `experiments/README.md`.

## Versionamento

- Desenvolvimento na `main`; **tags** para congelar versões reproduzíveis
  (`git tag -a inline-v1 -m "..."`), não branches paralelas de longa vida.
- Resultados que embasam conclusões ficam em `experiments/`; saídas transitórias (`output/`)
  são ignoradas pelo git.
