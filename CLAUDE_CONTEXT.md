# CLAUDE_CONTEXT.md — Classificador de Erros CodeBench (PIBIC/UFAM)

> Documento de handoff gerado em 2026-07-03.
> Autor: Guilherme (guilhermepereira0444@gmail.com)
> Contém decisões de design, estado atual do código, bugs corrigidos e pendências.

---

## 1. O QUE É O PROJETO

Sistema de análise dinâmica automática de código C submetido à plataforma **CodeBench** (juiz online da UFAM). É um protótipo de pesquisa PIBIC que:

1. Detecta erros de memória no código do aluno (buffer overflow, use-after-free, leaks)
2. Classifica o erro via LLM local (Ollama + qwen2.5-coder:7b)
3. Infere a complexidade assintótica Big-O do algoritmo via regressão estatística
4. Gera um CSV consolidado com diagnóstico forense por arquivo

**Ambiente de execução:** WSL (Ubuntu) dentro do Windows. O pipeline roda como `python3 orquestrador.py`.

---

## 2. ARQUITETURA: PIPELINE DETERMINÍSTICO EM CASCATA

```
Malha 1 (ASan + GDB)
    ↓ erro? → IA classifica → CSV (Complexidade = N/A)
    ↓ limpo?
Malha 2 (Valgrind + vgdb)
    ↓ erro? → IA classifica → CSV (Complexidade = N/A)
    ↓ limpo?
Malha 3 (perf stat / wall-time + regressão Big-O)
    ↓ → CSV (sem erro de memória + complexidade inferida)
```

**Princípio de cascata:** Malha 3 só executa se o código passou limpo nas malhas de memória. Razão: medir complexidade assintótica de código com Undefined Behavior é tecnicamente sem sentido.

**Princípio de agência local:** o LLM apenas interpreta resultados — o pipeline é determinístico, o LLM não toma decisões de fluxo.

---

## 3. ESTRUTURA DE ARQUIVOS

```
Classificador de Erros prototipo/
├── orquestrador.py                    ← ponto de entrada, orquestra as 3 malhas
├── src/
│   ├── ferramentas_analise_dinamica.py ← Malha 1 (ASan+GDB) e Malha 2 (Valgrind+vgdb)
│   ├── perfilador_desempenho.py        ← Malha 3 (perf stat / wall-time + Big-O)
│   ├── llm_client.py                  ← cliente Ollama com retry
│   └── parser_logs.py                 ← filtra log bruto antes de enviar ao LLM
├── codigos_alunos/                    ← arquivos .c a serem analisados
└── output/
    └── catalogo_erros_codebench.csv   ← saída final
```

**REGRA IMPORTANTE:** `perfilador_desempenho.py` é SEPARADO de `ferramentas_analise_dinamica.py` por decisão explícita do usuário. Nunca fundir.

---

## 4. ESTADO ATUAL DE CADA ARQUIVO

### 4.1 `orquestrador.py` — COMPLETO E FUNCIONAL

```python
from src.ferramentas_analise_dinamica import executar_malha_1_asan, executar_malha_2_valgrind
from src.perfilador_desempenho import executar_malha_3_desempenho
from src.parser_logs import limpar_log_gdb
from src.llm_client import classificar_erro
```

Fluxo:
- Itera sobre `./codigos_alunos/*.c`
- Malha 1 → Malha 2 → Malha 3 em cascata
- CSV com campos: `Arquivo, Ferramenta, Tipo Erro, Linha, Variaveis, Causa Raiz, Diagnostico, Complexidade, Metrica_Perf, Status_Malha3`
- Se há erro de memória: `Complexidade = "N/A (erro de memória detectado)"`, `Status_Malha3 = "não executada"`
- Se código limpo: popula campos de Malha 3

### 4.2 `src/ferramentas_analise_dinamica.py` — COMPLETO E FUNCIONAL

**Função auxiliar nova (adicionada para resolver hang):**
```python
def _stdin_para_analise(caminho_codigo):
    # Importa detectar_parametro_escala + gerar_entrada_para_n de perfilador_desempenho
    # Se o código tem scanf("%d", &n) + loop/malloc com n → gera "5\n1 2 3 4 5\n"
    # Senão → retorna None (herda stdin do ambiente)
```
**Por que foi necessário:** programas que leem N via scanf bloqueavam os subprocessos do GDB e do Valgrind esperando input do terminal. Apenas arquivos que crasham ANTES do scanf (ex: buffer overflow em array hardcoded) funcionavam antes.

**`executar_malha_1_asan(caminho_codigo)`:**
- Compila com `gcc -fsanitize=address -g`
- `ASAN_OPTIONS=abort_on_error=1:detect_leaks=0`
  - `detect_leaks=0`: LSan conflita com GDB via ptrace; leaks são delegados ao Valgrind
- Roda via `gdb -q --batch -ex run -ex "bt full" -ex quit`
- Agora passa `input=stdin_analise` e `timeout=60` no subprocess.run
- Detecta `"ERROR: AddressSanitizer"` na saída

**`executar_malha_2_valgrind(caminho_codigo)`:**
- Compila com `gcc -g` (sem ASan — instrumentações conflitam)
- Socket vgdb único: `/tmp/vgdb_{uuid4().hex[:8]}`
- Valgrind com `--vgdb-error=1 --leak-check=full`
- **Novo:** `stdin=subprocess.PIPE` no Popen + write síncrono do stdin_analise + `stdin.close()`
- `time.sleep(1.5)` para vgdb inicializar
- GDB conecta via `target remote | vgdb --vgdb-prefix=...`
- Detecta erro via `"monitor command request to kill this process"` (GDB) ou `"definitely lost"` / `ERROR SUMMARY != 0` (Valgrind)
- **Novo:** `communicate(timeout=120)` com fallback `kill()` contra hang

### 4.3 `src/perfilador_desempenho.py` — COMPLETO E FUNCIONAL

**Estrutura em 5 blocos:**

**Pré-check (novo):**
```python
def _perf_disponivel():
    # Roda "perf stat -- true" com timeout=3s
    # Em WSL, perf existe mas trava tentando acessar PMU do hypervisor
    # Sem este check: 8 × 30s = ~4min de travamento antes do fallback

_PERF_DISPONIVEL: bool | None = None  # cache global por processo

def _checar_perf():
    # Chama _perf_disponivel() uma vez, cacheia, imprime status
```

**Bloco 1 — `detectar_parametro_escala(codigo_fonte)`:**
- Remove comentários `//` e `/* */`
- Busca `scanf("%d", &var)` com EXATAMENTE um `%d` (exclui `"%d %d"`)
- Confirma que `var` aparece em: `for(;;var;;)`, `while(var)`, `malloc(var)`, `calloc(var)`, `arr[var]`
- Retorna nome da variável (Cenário A) ou `None` (Cenário B)

**Bloco 2 — `gerar_entrada_para_n(N, formato="N_ESPACO_VALORES")`:**
- Padrão: `"N\n1 2 3 ... N\n"` (compatível com `scanf` em loop)
- Variante: `"N_LINHA_POR_LINHA"` → um valor por linha
- Usa valores 1..N (não constante) para evitar branch predictor do CPU otimizar artificialmente

**Bloco 3 — Coleta de métricas:**
```python
LIMIAR_RUIDO_NS = 2_000_000  # 2ms — abaixo disso é overhead de fork/exec, não do algoritmo

def coletar_instrucoes_perf(binario, stdin_input, timeout=30):
    # Retorna None imediatamente se _checar_perf() == False (evita hang)
    # perf stat -e instructions:u → conta instruções do espaço de usuário
    # Aceita separadores "," (en_US) e "." (pt_BR) no número

def coletar_tempo_parede_ns(binario, stdin_input, n_medicoes=5, timeout=15):
    # Fallback: mediana de 5 medições com perf_counter_ns()
    # Mediana resiste a outliers de scheduler; 5 medições = protótipo rápido
    # Retorna None se < 3 execuções bem-sucedidas

def coletar_metrica(binario, stdin_input):
    # 1. Tenta perf_stat; 2. Fallback wall_time; 3. Descarta se < LIMIAR_RUIDO_NS
```

**Bloco 4 — `inferir_big_o(resultados, entradas)`:**
- Regressão por Mínimos Quadrados Não-Lineares (`scipy.optimize.curve_fit`)
- Normaliza Y pelo máximo (estabilidade numérica para valores na escala de bilhões)
- Modelos testados: O(1), O(log N), O(N), O(N log N), O(N²), O(N³), O(2^N)
- Seleciona modelo com maior R²
- Retorna: `"O(N log N) - Log-Linear (R²=0.9987, confiança alta)"`
- Confiança: alta (R²>0.98), média (R²>0.90), baixa (R²≤0.90)
- **BUG ANTIGO CORRIGIDO:** chaves do dict eram float vs. int → `int(n)` em todas as comparações

**Bloco 5 — `executar_malha_3_desempenho(caminho_codigo)`:**
```python
TAMANHOS_ESCALA_PERF = [10, 50, 100, 500, 1000, 5000, 10000]  # quando perf disponível
TAMANHOS_ESCALA_TIME = [100, 200, 1_000, 2_000, 4_000]         # fallback de tempo
```
- Compila com `gcc -O0 -g` (sem otimizações para medir o algoritmo real)
- Cenário B: retorna `{"status": "nao_aplicavel", "complexidade_inferida": "N/A — Exercício de Entrada Fixa"}`
- Cenário A: `_checar_perf()` → seleciona escala → coleta métricas → regressão

### 4.4 `src/llm_client.py` — COMPLETO E FUNCIONAL

```python
URL_LLM_LOCAL = "http://172.30.0.1:11434/api/generate"
NOME_MODELO = "qwen2.5-coder:7b"
```

**Arquitetura de retry (adicionada nesta sessão):**
```python
def _chamar_llm(prompt, tentativa=1):
    # POST com stream=True, format="json"; concatena tokens; imprime em tempo real

def _sanitizar(texto):
    # Remove ```json, ```, espaços

def classificar_erro(log_limpo, codigo_fonte="", max_tentativas=3):
    # Loop de retry com backoff exponencial: 1s, 2s, 4s
    # Trata: resposta vazia (Ollama sobrecarregado), JSONDecodeError, erros de rede
    # Retorna dict de fallback após esgotar tentativas (não trava o pipeline)
```

**Prompt envia:**
- Log filtrado pelo parser
- Código-fonte do aluno (enriquece contexto: tipos, escopos, linhas)
- Solicita JSON com: `tipo_erro, linha_ocorrencia, variaveis_envolvidas, causa_raiz, descricao_curta`

### 4.5 `src/parser_logs.py` — FUNCIONAL (Layer 1 apenas)

Filtra log bruto linha a linha. Filtros em ordem:
1. **Guilhotina:** para ao encontrar `"Shadow bytes"` (dump hexadecimal do ASan — puro ruído)
2. **Anti-dump:** descarta linhas com > 300 chars
3. **Alertas críticos:** ASan (`ERROR:`, `heap-buffer-overflow`, `stack-buffer-overflow`, `use-after-free`, `double-free`, `SEGV`) e Valgrind (`Conditional jump`, `definitely lost`, `indirectly lost`, `Invalid`, `Uninitialized`)
4. **Contexto de memória:** `Address 0x...`, `previously allocated`, `freed by`
5. **Tipo de acesso:** `READ of size N`, `WRITE of size N`
6. **Rastreio no arquivo do aluno:** linhas com `nome_arquivo` no backtrace
7. **Variáveis locais GDB:** linhas com `=` que não começam com `==`, ` ` ou `__`

---

## 5. BUGS CORRIGIDOS NESTA SESSÃO (com raiz e solução)

### Bug 1: ImportError — `cannot import name 'executar_malha_3_desempenho'`
- **Raiz:** Write tool escrevia no sandbox de montagem WSL, não no disco Windows real. O arquivo no disco ainda tinha o conteúdo antigo (só `inferir_big_o`).
- **Solução:** Usar o caminho Windows completo `C:\Users\guisp\Área de Trabalho\...` no Write tool.

### Bug 2: `ValueError: source code string cannot contain null bytes`
- **Raiz:** O arquivo antigo era maior que o novo. Após sobrescrever, sobraram 1497 bytes nulos no final (offset 21208+).
- **Solução:** Ler como bytes, `.replace(b'\x00', b'')`, escrever de volta como UTF-8.

### Bug 3: `IndentationError: expected an indented block after 'if' statement`
- **Raiz:** Edit deixou `if metrica_fonte is None:` com corpo de espaços em branco.
- **Solução:** Manipulação direta da string Python com `.replace()` para inserir `metrica_fonte = fonte`.

### Bug 4: pyc cache carregando versão antiga
- **Raiz:** `__pycache__/perfilador_desempenho.cpython-310.pyc` era read-only (mount NTFS), Python carregava bytecode antigo.
- **Solução no ambiente:** `.pyc` é regenerado automaticamente quando o `.py` tem mtime mais recente. No teste manual: `exec(compile(open(file).read(), ...))` para bypass.

### Bug 5: Ollama retornando resposta vazia (JSON inválido)
- **Raiz:** Ollama momentaneamente sobrecarregado retorna stream sem tokens.
- **Solução:** Retry com backoff exponencial em `classificar_erro()`.

### Bug 6: float/int key bug em `inferir_big_o`
- **Raiz:** `x_data = np.array([...], dtype=float)` gerava chaves float, mas dict tinha chaves int → KeyError.
- **Solução:** `ns_validos = [n for n in entradas if int(n) in resultados]` e `resultados[int(n)]`.

### Bug 7: Malha 3 travando em WSL (perf stat)
- **Raiz:** `perf` existe em WSL mas trava tentando acessar PMU do hypervisor. Com 7 tamanhos + 1 sonda, causava 8 × 30s = ~4min de travamento.
- **Solução:** `_perf_disponivel()` roda `perf stat -- true` com timeout=3s antes de qualquer medição. Resultado cacheado em `_PERF_DISPONIVEL`.

### Bug 8: Malha 1 e 2 travando para códigos que leem scanf
- **Raiz:** `subprocess.run(GDB)` e `subprocess.Popen(Valgrind)` não forneciam stdin. Programas com `scanf("%d", &n)` ficavam aguardando input do terminal.
- **Solução:** `_stdin_para_analise()` detecta se o código tem parâmetro de escala e gera `"5\n1 2 3 4 5\n"`. Passado via `input=` (GDB) e `stdin=PIPE` + write síncrono (Valgrind).

### Bug 9: N=50000/100000 travando a Malha 3
- **Raiz:** `TAMANHOS_ESCALA_TIME = [1000, 5000, 10000, 50000, 100000]` com `n_medicoes=9` e `timeout=30s` = potencialmente minutos por arquivo.
- **Solução:** Reduzido para `[100, 200, 1000, 2000, 4000]`, `n_medicoes=5`, `timeout=15s`.

---

## 6. DECISÕES DE DESIGN (com justificativas)

| Decisão | Razão |
|---|---|
| Malha 1 usa `detect_leaks=0` | LSan conflita com GDB via ptrace; leaks são detectados melhor pelo Valgrind (Malha 2) com estado de variáveis via vgdb |
| Malha 3 só roda após Malha 1+2 limpas | Comportamento assintótico de código com UB é indefinido |
| `perf stat -e instructions:u` em vez de wall time | Instruções de CPU são determinísticas; wall time varia com carga do servidor |
| Escala diferente para perf vs. time | HPC conta instruções absolutas (sinal desde N=10); wall time precisa de N maior para superar limiar de 2ms |
| `LIMIAR_RUIDO_NS = 2_000_000` | Abaixo de 2ms, o overhead de fork+exec+I/O domina sobre o algoritmo medido |
| Y-normalizado antes da regressão | Valores na escala de bilhões causam overflow numérico no `curve_fit` |
| `gcc -O0` na Malha 3 | Com otimizações, o compilador pode eliminar loops e mascarar a complexidade real |
| Valores 1..N no stdin gerado | Constantes iguais ativariam otimizações do branch predictor da CPU, distorcendo a medição |
| `n_medicoes=5` (era 9) | Protótipo — mediana de 5 já é estatisticamente válida para Big-O; 9 era excessivo |

---

## 7. DOIS CENÁRIOS DE EXERCÍCIO (arquitetura core)

### Cenário A — Template CodeBench (exercício escalável)
```c
int main() {
    int n;
    scanf("%d", &n);       // ← detectado por detectar_parametro_escala()
    int *v = malloc(n * sizeof(int));
    // ... lê n elementos e processa
    free(v);
}
```
→ Malha 3 injeta N crescente, mede, faz regressão, retorna complexidade Big-O.

### Cenário B — Exercício de entrada fixa
```c
int main() {
    int a, b, c;
    scanf("%d %d %d", &a, &b, &c);  // ← três %d, não detectado
    printf("%d\n", (a + b + c) / 3);
}
```
→ Malha 3 retorna `{"status": "nao_aplicavel", "complexidade_inferida": "N/A — Exercício de Entrada Fixa"}`.
→ Justificativa no campo `detalhes`: professor pode anotar variável de escala no cadastro do exercício.

---

## 8. PENDÊNCIAS / PRÓXIMAS FASES

### Pendências técnicas imediatas
- **Validar pipeline completo end-to-end** após as correções de hang (Bug 7, 8, 9). Última execução mostrava Malha 3 rodando com escala antiga antes dos fixes.
- **Testar Cenário B** (arquivo como `teste_lista_sem_erro.c` ou similar sem scanf de N) para confirmar que retorna "N/A" corretamente.

### Parser Unificado (Camadas 2 e 3 não implementadas)
- **Layer 2 — RIN (Representação Intermediária Normalizada):** dataclass Python independente da ferramenta fonte (ASan vs. Valgrind). Ainda não existe.
- **Layer 3 — Serializador de token budget:** limitar output a ~300 tokens para o LLM, deduplicar erros em cascata. Ainda não existe.
- **Parser XML do Valgrind:** o parser atual só trata texto; Valgrind tem saída XML (`--xml=yes`) mais estruturada. Não implementado.

### RAG e prompt avançado (fases futuras)
- **RAG:** LlamaIndex + FAISS para recuperação híbrida (dense + BM25). Não implementado.
- **Prompt 4-pilares:** Socrático, com mecanismo Reflexion, baseado em literatura pedagógica. Não implementado.
- O prompt atual é funcional mas básico — solicita JSON com 5 campos.

---

## 9. CONFIGURAÇÃO DO AMBIENTE

```
LLM local: Ollama em http://172.30.0.1:11434
Modelo:    qwen2.5-coder:7b
Runtime:   Python 3.13 (WSL Ubuntu)
Deps:      requests, numpy, scipy
Ferramentas: gcc, gdb, valgrind, perf (perf indisponível em WSL sem PMU)
```

**perf no WSL:** `/proc/sys/kernel/perf_event_paranoid` geralmente = 3 (bloqueado). Para habilitar: `echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid`. Se habilitado, `TAMANHOS_ESCALA_PERF = [10, 50, 100, 500, 1000, 5000, 10000]` será usado automaticamente.

---

## 10. COMO RETOMAR O TRABALHO

1. Abrir pasta `C:\Users\guisp\Área de Trabalho\Estudos\Ciência da Computação - UFAM\PIBIC\Classificador de Erros prototipo`
2. Garantir Ollama rodando com `qwen2.5-coder:7b`
3. Rodar `python3 orquestrador.py` no WSL
4. Verificar saída esperada para `teste_vetor_quicksort.c`:
   ```
   [Analisando] teste_vetor_quicksort.c
     -> Código sem erros de memória. Executando Malha 3 (perfilamento)...
     -> [Malha 3] perf stat: indisponível — usando fallback de tempo
     -> [Malha 3] Parâmetro de escala: 'n' | Escala: [100, 200, 1000, 2000, 4000]
        N=    100: ...
        N=    200: ...
        ...
     -> [Malha 3] Complexidade inferida: O(N log N) - Log-Linear (R²=..., confiança ...)
   ```

---

## 11. ARQUIVOS .C DE TESTE DISPONÍVEIS

```
codigos_alunos/
├── teste_asan.c                  ← buffer overflow (Malha 1 detecta)
├── teste_bubbleSort_val...       ← provavelmente leak (Malha 2 detecta)
├── teste_lista_encadeada.c       ← lista com leak (Malha 2 detecta)
├── teste_lista_sem_erro.c        ← lista sem erro (vai para Malha 3)
├── teste_variavel_nao_ini...     ← uninitialized-value (Malha 2 detecta)
└── teste_vetor_quicksort.c       ← quicksort correto (Malha 3: O(N log N))
```
