"""
Malha 3: Perfilamento Algorítmico e Inferência de Complexidade Assintótica
=========================================================================

Implementa o Perfilamento Algorítmico conforme descrito na arquitetura proposta.

IDEIA CENTRAL:
    Em vez de medir o tempo de parede (que varia com a carga do servidor),
    submetemos o binário a entradas de tamanho crescente (N=10, 100, 1000...)
    e contamos quantas instruções o CÓDIGO DO ALUNO executou para cada N
    (isolando-o do I/O da libc). Com esses pontos, uma regressão infere a curva Big-O.

DOIS CENÁRIOS POSSÍVEIS:
    Cenário A — Exercício com template CodeBench (ex: "leia N e ordene N números"):
        O orquestrador injeta N pelo stdin e varia o tamanho livremente.
        → Análise de complexidade completa é possível.

    Cenário B — Exercício de entrada fixa (ex: "some 3 números"):
        N não pode ser variado sem reescrever o código do aluno.
        → Análise marcada como N/A com justificativa.
"""

import re
import os                       # caminhos e arquivo temporário do callgrind
import shutil                   # remove o diretório temporário do binário nativo
import tempfile                 # arquivos/dirs temporários (relatório do callgrind e binário nativo)
import subprocess
import warnings

import numpy as np
from scipy.optimize import curve_fit


# ══════════════════════════════════════════════════════════════════════════════
# PRÉ-CHECK: DISPONIBILIDADE DO CALLGRIND (VALGRIND)
# ══════════════════════════════════════════════════════════════════════════════

def _callgrind_disponivel():
    """
    Verifica se o Valgrind (ferramenta Callgrind) está instalado.

    Callgrind, não `perf` nem Cachegrind: o `perf` lê contadores de hardware (PMU),
    indisponíveis em WSL/contêineres; o Cachegrind conta por emulação (sem PMU), mas só dá o
    TOTAL do programa (mistura algoritmo e I/O); o Callgrind também emula, porém atribui as
    instruções por FUNÇÃO e por OBJETO (executável x libc), permitindo somar só o binário do
    aluno e isolar o custo do algoritmo. Verificação leve; a robustez do parsing fica em
    coletar_instrucoes_callgrind().
    """
    try:
        resultado = subprocess.run(
            ["valgrind", "--version"],
            capture_output=True,
            text=True,
            timeout=5          # `valgrind --version` responde instantaneamente
        )
        return "valgrind" in (resultado.stdout + resultado.stderr).lower()
    except Exception:
        return False


# Cache do resultado: executado uma vez por processo, evita re-check a cada medição
_CALLGRIND_DISPONIVEL: bool | None = None

def _checar_callgrind():
    """Retorna (e cacheia) a disponibilidade do Callgrind para este processo."""
    global _CALLGRIND_DISPONIVEL
    if _CALLGRIND_DISPONIVEL is None:
        _CALLGRIND_DISPONIVEL = _callgrind_disponivel()
        status = "disponível" if _CALLGRIND_DISPONIVEL else "indisponível — usando fallback de tempo"
        print(f"  -> [Malha 3] Callgrind (contagem de instruções do aluno): {status}")
    return _CALLGRIND_DISPONIVEL


# ══════════════════════════════════════════════════════════════════════════════
# BLOCO 1 — DETECÇÃO DO MODO DE ENTRADA
# ══════════════════════════════════════════════════════════════════════════════

def detectar_parametro_escala(codigo_fonte):
    """
    Determina se o código tem um parâmetro de tamanho N controlável via stdin (Cenário A) ou não
    (Cenário B). Retorna o nome da variável de escala (ex.: "n", "k") ou None.

    Duas etapas: (1) encontra um scanf que lê EXATAMENTE um inteiro — scanf("%d", &var), excluindo
    formatos compostos como "%d %d"; (2) confirma que a variável controla um laço ou uma alocação
    dinâmica, ou seja, representa o "tamanho" do problema.
    """

    # Remove comentários (// e /* */) antes de analisar, para não detectar um scanf comentado.
    codigo = re.sub(r'//.*', '', codigo_fonte)
    codigo = re.sub(r'/\*.*?\*/', '', codigo, flags=re.DOTALL)

    # scanf que lê EXATAMENTE um inteiro ("%d"); group(2) captura a variável.
    # Aceita scanf("%d", &n); rejeita scanf("%d %d", &a, &b) (entrada composta).
    matches = list(re.finditer(
        r'scanf\s*\(\s*"(%d)"\s*,\s*&\s*(\w+)\s*\)',
        codigo
    ))

    for m in matches:
        var = m.group(2)  # nome da variável lida pelo scanf

        # Confirma que a variável representa o "tamanho": limite de laço ou tamanho de alocação.
        usada_como_tamanho = (
            re.search(rf'for\s*\([^;]*;\s*[^;]*{re.escape(var)}[^;]*;', codigo)  # limite de for
            or re.search(rf'while\s*\([^)]*{re.escape(var)}', codigo)            # condição de while
            or re.search(rf'malloc\s*\([^)]*{re.escape(var)}', codigo)           # qtd em malloc
            or re.search(rf'calloc\s*\([^)]*{re.escape(var)}', codigo)           # qtd em calloc
            or re.search(rf'\[\s*{re.escape(var)}\s*\]', codigo)                 # VLA int arr[var]
        )

        if usada_como_tamanho:
            return var

    return None   # Cenário B (entrada fixa)


# ══════════════════════════════════════════════════════════════════════════════
# BLOCO 2 — GERAÇÃO DE ENTRADAS ESCALONADAS
# ══════════════════════════════════════════════════════════════════════════════

def gerar_entrada_para_n(N, formato="N_ESPACO_VALORES"):
    """
    Gera a string enviada pelo stdin para um dado N.
    Padrão CodeBench mais comum: linha 1 com N, linha 2 com N inteiros separados por espaço.
    Compatível com scanf("%d", &arr[i]) em loop ou em linha única (o %d ignora whitespace).
    """
    if formato == "N_ESPACO_VALORES":
        # N inteiros crescentes (1..N): valores crescentes evitam que o branch predictor da CPU
        # otimize artificialmente o código durante a medição.
        valores = " ".join(str(i + 1) for i in range(N))
        return f"{N}\n{valores}\n"  # ex.: "5\n1 2 3 4 5\n"

    elif formato == "N_LINHA_POR_LINHA":
        # Variante com cada valor em uma linha (alguns exercícios pedem isso).
        valores = "\n".join(str(i + 1) for i in range(N))
        return f"{N}\n{valores}\n"  # ex.: "5\n1\n2\n3\n4\n5\n"

    # Fallback: apenas N, sem dados adicionais.
    return f"{N}\n"


# ══════════════════════════════════════════════════════════════════════════════
# BLOCO 3 — COLETA DE MÉTRICAS DE DESEMPENHO
# ══════════════════════════════════════════════════════════════════════════════

def _somar_ir_do_binario(caminho_out, nome_binario):
    """
    Usa a ferramenta nativa `callgrind_annotate` para fazer o parsing.
    Delega ao Valgrind a tarefa complexa de descomprimir IDs e grafos de chamadas,
    lendo o resultado já processado, limpo e formatado.
    """
    import subprocess
    
    total = 0
    alvo = f"[{nome_binario}]"  # ex: "[/tmp/malha3_xyz/bin_nativo]"

    try:
        # --threshold=100 é CRÍTICO: garante que TODAS as funções sejam listadas, 
        # mesmo as minúsculas que consomem < 0.1% (essencial para N pequenos como N=100).
        resultado = subprocess.run(
            ["callgrind_annotate", "--threshold=100", caminho_out],
            capture_output=True,
            text=True,
            check=True
        )
        
        # O output do callgrind_annotate tem o formato:
        # 405,220 (11.08%)  arquivo.c:particionar [/tmp/bin_nativo]
        for linha in resultado.stdout.splitlines():
            linha_limpa = linha.rstrip()
            
            # As linhas de sumário de função terminam sempre com o nome do objeto entre parêntesis retos
            if linha_limpa.endswith(alvo):
                partes = linha_limpa.split()
                
                if len(partes) >= 3:
                    # A 1ª coluna é a contagem de instruções (removemos as vírgulas)
                    ir_str = partes[0].replace(',', '')
                    
                    # Penúltima coluna: a assinatura (ex.: "arquivo.c:nome_da_funcao" ou "nome_da_funcao")
                    assinatura = partes[-2]
                    nome_fn = assinatura.split(':')[-1]

                    # Remove ruído: exclui a libc (outro objeto, já filtrado pelo alvo), o main (pelo
                    # nome) e as funções de arranque (_start, __libc_csu_init, etc., pelo prefixo _).
                    if nome_fn != 'main' and not nome_fn.startswith('_'):
                        try:
                            total += int(ir_str)
                        except ValueError:
                            pass
                            
    except Exception as e:
        print(f"Erro ao processar callgrind_annotate: {e}")
        
    return total
def coletar_instrucoes_callgrind(binario, stdin_input, timeout=180):
    """
    Executa o binário sob o Callgrind (Valgrind) e retorna o total de instruções
    (Ir) executadas SOMENTE dentro do binário do aluno, isolando o algoritmo do
    custo de I/O (scanf/printf) e de inicialização, que ficam na libc.

    Por que Callgrind por objeto e não o total do Cachegrind?
        O total do programa é dominado pelo I/O (O(N)), que mascara o algoritmo.
        O Callgrind atribui o custo por função/objeto; somando só o objeto do
        aluno, o I/O da libc sai fora e a complexidade real fica visível.

    Custo: a emulação do Valgrind é ~20–100× mais lenta que a execução nativa;
        por isso o timeout é generoso e a escala de N é contida.

    Retorna o número de instruções (int) ou None se o Callgrind não estiver
    disponível ou falhar.
    """
    # Curto-circuito: se o pré-check já sabe que o Valgrind não está disponível.
    if not _checar_callgrind():
        return None

    # Cria um arquivo temporário para receber o relatório detalhado do callgrind.
    fd, caminho_out = tempfile.mkstemp(prefix="callgrind_", suffix=".out")  # (descritor, caminho)
    os.close(fd)                 # só queremos o caminho; quem escreve no arquivo é o valgrind

    try:
        subprocess.run(
            [
                "valgrind", "--tool=callgrind",          # usa o Callgrind (conta Ir por função/objeto)
                "--cache-sim=no", "--branch-sim=no",     # sem simular cache/desvio: só a contagem de instruções (evento Ir)
                "--callgrind-out-file=" + caminho_out,   # grava o relatório neste arquivo temporário
                binario                                  # executável do aluno a ser perfilado
            ],
            input=stdin_input,       # injeta a entrada gerada pelo gerar_entrada_para_n()
            capture_output=True,     # não polui o terminal com a saída do programa/valgrind
            text=True,
            timeout=timeout          # teto de tempo (a emulação é lenta para N grande)
        )

        # Faz o parsing do arquivo somando o Ir só do binário do aluno (exclui libc).
        total = _somar_ir_do_binario(caminho_out, binario)
        return total if total > 0 else None   # 0 = nada casou (falha de parsing) -> trata como None

    except FileNotFoundError:
        return None   # `valgrind` não está instalado — cai para o fallback de tempo
    except subprocess.TimeoutExpired:
        return None   # a emulação estourou o tempo neste N — descarta o ponto
    except Exception:
        return None   # qualquer outro erro inesperado — descarta silenciosamente
    finally:
        # Remove o arquivo temporário (com ou sem sucesso) para não acumular lixo em /tmp.
        try:
            os.remove(caminho_out)
        except OSError:
            pass


# Piso de ruído do fallback de tempo: medições abaixo de 2ms estão no overhead
# de fork + exec + I/O do subprocess — não refletem o algoritmo em si.
# Pontos abaixo deste limiar são descartados antes da regressão.
LIMIAR_RUIDO_NS = 2_000_000  # 2 ms em nanosegundos


def coletar_tempo_parede_ns(binario, stdin_input, n_medicoes=5, timeout=15):
    """
    Fallback quando o Callgrind não está disponível.

    Mede o tempo de execução usando perf_counter_ns() (resolução de nanosegundos)
    e retorna a MEDIANA de 5 medições para reduzir o jitter do scheduler do SO.

    Por que mediana e não média?
        A média é sensível a outliers (picos de latência do SO).
        A mediana representa a execução "típica" sem ser distorcida por picos.

    Retorna o tempo mediano em nanosegundos (int) ou None se < 3 execuções bem-sucedidas.
    """
    import time as _time

    tempos = []
    for _ in range(n_medicoes):
        try:
            t0 = _time.perf_counter_ns()  # marca o início com resolução de nanosegundos
            resultado = subprocess.run(
                [binario],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            t1 = _time.perf_counter_ns()  # marca o fim

            # Só contabiliza se o programa encerrou corretamente (sem crash)
            if resultado.returncode == 0:
                tempos.append(t1 - t0)  # tempo total em nanosegundos para este N
        except Exception:
            continue  # execução falhou (timeout, crash) — descarta esta medição

    # Exige pelo menos 3 execuções bem-sucedidas para a mediana ser estatisticamente válida
    if len(tempos) < 3:
        return None

    tempos.sort()
    return tempos[len(tempos) // 2]  # índice do meio = mediana da lista ordenada


def coletar_metrica(binario, stdin_input):
    """
    Seleciona e executa a melhor métrica disponível para medir o custo do algoritmo:

    1ª opção: Callgrind (instruções do aluno, "Ir" por objeto) — determinístico, isola o algoritmo do I/O
    2ª opção: mediana de tempo de parede em ns — usado quando o Callgrind não está disponível

    Se o tempo medido for menor que LIMIAR_RUIDO_NS (2ms), descarta o ponto:
    ele está no piso de overhead do subprocess, não no algoritmo.

    Retorna (valor, fonte) onde fonte identifica qual método foi usado,
    ou (None, None) se ambos falharem ou o valor estiver abaixo do limiar.
    """
    # Tenta primeiro o método de referência (instruções do aluno via Callgrind, por objeto)
    instrucoes = coletar_instrucoes_callgrind(binario, stdin_input)
    if instrucoes is not None:
        return instrucoes, "callgrind (Ir aluno)"  # retorna imediatamente com o melhor método

    # Fallback: mediana de tempo de parede em nanosegundos
    tempo_ns = coletar_tempo_parede_ns(binario, stdin_input)

    # Descarta pontos abaixo do limiar de ruído — não representam o algoritmo
    if tempo_ns is not None and tempo_ns >= LIMIAR_RUIDO_NS:
        return tempo_ns, "wall_time_ns (fallback)"

    return None, None  # ambos os métodos falharam ou ponto abaixo do limiar


# ══════════════════════════════════════════════════════════════════════════════
# BLOCO 4 — REGRESSÃO ESTATÍSTICA (INFERÊNCIA DE BIG-O)
# ══════════════════════════════════════════════════════════════════════════════

def inferir_big_o(resultados, entradas):
    """
    Recebe os pontos coletados {N: métrica} e determina qual curva Big-O
    melhor descreve o crescimento do custo do algoritmo com o tamanho da entrada.

    MÉTODO: Regressão de Mínimos Quadrados Não-Lineares (scipy curve_fit).
        Para cada família de complexidade (O(N), O(N²), etc.), ajusta
        uma curva f(x) = c * g(x) aos dados e mede o R² do ajuste.
        O modelo com maior R² vence.

    POR QUE R²?
        R² mede "qual fração da variação dos dados é explicada pelo modelo".
        R² = 1.0 → ajuste perfeito. R² < 0.90 → nenhum modelo padrão encaixa bem.

    O PARÂMETRO 'c':
        Cada modelo tem uma constante multiplicativa 'c' que absorve fatores
        de hardware (cache, pipeline, loop unrolling) — assim comparamos apenas
        a forma da curva, não a escala absoluta dos números.
    """

    # Exige pelo menos 3 pontos para que a regressão tenha significado estatístico
    if len(resultados) < 3:
        return "Indeterminada (pontos insuficientes — mínimo: 3)"

    # Garante que as chaves do dict são int (evita bug de float key vs int key)
    ns_validos = [n for n in entradas if int(n) in resultados]
    x_data = np.array(ns_validos, dtype=float)                             # valores de N (eixo X)
    y_data = np.array([resultados[int(n)] for n in ns_validos], dtype=float)  # métricas (eixo Y)

    # Normaliza Y para o intervalo [0, 1] dividindo pelo máximo.
    # Isso garante estabilidade numérica no curve_fit — sem normalização,
    # números na escala de bilhões (instruções de CPU) causam overflow no solver.
    y_max = np.max(y_data)
    y_norm = y_data / y_max if y_max > 0 else y_data

    # Famílias assintóticas testadas — cobrindo os casos típicos de CS1/CS2
    # Cada lambda é f(x, c) = c * g(x), onde c é o parâmetro livre ajustado
    modelos = {
        "O(1) - Constante":        lambda x, c, c0: c * np.ones_like(x) + c0,
        "O(log N) - Logarítmica":  lambda x, c, c0: c * np.log2(np.maximum(x, 1.0)) + c0,
        "O(N) - Linear":           lambda x, c, c0: c * x + c0,
        "O(N log N) - Log-Linear": lambda x, c, c0: c * x * np.log2(np.maximum(x, 1.0)) + c0,
        "O(N²) - Quadrática":      lambda x, c, c0: c * (x ** 2) + c0,
        "O(N³) - Cúbica":          lambda x, c, c0: c * (x ** 3) + c0,
        "O(2^N) - Exponencial":    lambda x, c, c0: c * (2.0 ** np.minimum(x, 60.0)) + c0,
    }   

    melhor_modelo = "Indeterminada"
    melhor_r2 = -float('inf')

    warnings.filterwarnings("ignore")
    for nome, func in modelos.items():
        try:
            # Agora p0 precisa de dois palpites iniciais [c, c0]
            # Usamos [1.0, 0.1] como ponto de partida seguro para dados normalizados
            popt, _ = curve_fit(func, x_data, y_norm, p0=[1.0, 0.1], maxfev=20000)

            y_pred = func(x_data, *popt)

            ss_res = np.sum((y_norm - y_pred) ** 2)
            ss_tot = np.sum((y_norm - np.mean(y_norm)) ** 2)
            r2 = 1.0 - (ss_res / ss_tot) if ss_tot != 0 else 1.0

            if r2 > melhor_r2:
                melhor_r2 = r2
                melhor_modelo = nome

        except Exception:
            continue

    warnings.resetwarnings()  # restaura o filtro de warnings após a busca

    # Classifica a confiança com base no R² do melhor modelo
    confianca = (
        "alta"  if melhor_r2 > 0.98 else   # curva praticamente perfeita sobre os dados
        "média" if melhor_r2 > 0.90 else   # boa correlação, mas com alguma variância residual
        "baixa — verificar manualmente"    # nenhum modelo padrão encaixa bem — revisar manualmente
    )

    return f"{melhor_modelo} (R²={melhor_r2:.4f}, confiança {confianca})"


# ══════════════════════════════════════════════════════════════════════════════
# BLOCO 5 — ORQUESTRAÇÃO DA MALHA 3
# ══════════════════════════════════════════════════════════════════════════════

# Escala usada com o Callgrind. A contagem de instruções é exata e determinística
# desde entradas pequenas, então não é preciso N gigante; como a emulação é lenta
# (~20–100×), limitamos o teto para a análise completar em tempo razoável.
TAMANHOS_ESCALA_INSTRUCOES = [100, 500, 1000, 2000, 5000, 10000]

# Escala usada no fallback de tempo de parede.
# Valores menores para que a análise complete em segundos, não minutos.
# N=100..4000 já gera sinal suficiente acima do limiar de 2ms para algoritmos O(N log N) ou piores.
TAMANHOS_ESCALA_TIME = [100, 200, 1_000, 2_000, 4_000]

# Alias de compatibilidade — mantido caso algum módulo importe TAMANHOS_ESCALA diretamente
TAMANHOS_ESCALA = TAMANHOS_ESCALA_INSTRUCOES


def executar_malha_3_desempenho(caminho_codigo):
    """
    Orquestra as três fases do perfilamento algorítmico:
      1. Compila o código sem instrumentação (execução pura, sem overhead de ASan/Valgrind)
      2. Detecta o cenário de entrada e coleta métricas para entradas escalonadas
      3. Infere a complexidade Big-O por regressão estatística

    Retorna um dict com:
        status               → "sucesso" | "nao_aplicavel" | "dados_insuficientes" | "erro_compilacao"
        complexidade_inferida→ string Big-O (ex: "O(N²)") ou "N/A"
        metrica_usada        → "callgrind (Ir aluno)" | "wall_time_ns (fallback)" | None
        dados_coletados      → {N: métrica} — pontos usados na regressão
        detalhes             → mensagem explicativa para log e debug
    """

    # Cria diretório no /tmp (que no WSL é resolvido via tmpfs ou sistema nativo).
    # Isso impede que o Callgrind perca inodes e deixe objetos com nome em branco (atrito NTFS).
    temp_dir = tempfile.mkdtemp(prefix="malha3_")
    binario_saida = os.path.join(temp_dir, "bin_nativo")

    try:
        # ── FASE 1: Compilação nativa sem instrumentação ──────────────────────────
        # -O0 desativa otimizações do compilador para medir o algoritmo do aluno,
        # não a versão otimizada que mascararia a complexidade real (ex: loop eliminado pelo GCC).
        # -g mantém símbolos de debug mínimos para rastreabilidade em caso de crash.
        compilacao = subprocess.run(
            ["gcc", "-O0", "-g", "-o", binario_saida, caminho_codigo],
            capture_output=True, text=True
        )
        if compilacao.returncode != 0:
            # Retorna o erro do compilador diretamente — sem código compilado, não há o que medir
            return {
                "status": "erro_compilacao",
                "complexidade_inferida": "N/A",
                "metrica_usada": None,
                "dados_coletados": {},
                "detalhes": compilacao.stderr.strip()
            }

        # ── FASE 2: Detecção do cenário de entrada ────────────────────────────────
        with open(caminho_codigo, 'r', encoding='utf-8', errors='replace') as f:
            codigo_fonte = f.read()

        # Analisa o código-fonte para encontrar uma variável de escala controlável
        var_escala = detectar_parametro_escala(codigo_fonte)

        # ── CENÁRIO B: Entrada fixa — análise não aplicável ───────────────────────
        if var_escala is None:
            return {
                "status": "nao_aplicavel",
                "complexidade_inferida": "N/A — Exercício de Entrada Fixa",
                "metrica_usada": None,
                "dados_coletados": {},
                "detalhes": (
                    "Nenhum parâmetro de tamanho escalável detectado no código. "
                    "Heurística: busca por `scanf(\"%d\", &var)` seguido de loop ou "
                    "alocação de tamanho `var`. "
                    "Exercícios de entrada fixa não permitem inferência de complexidade "
                    "assintótica via escalagem de N. "
                    "Alternativa futura: o professor anota a variável de escala no "
                    "cadastro do exercício na plataforma."
                )
            }

        # ── CENÁRIO A: Entrada escalável — executa o perfilamento ─────────────────
        # _checar_callgrind() verifica UMA VEZ se o Valgrind está instalado e cacheia
        # o resultado. O Callgrind conta instruções por emulação (sem PMU) e por objeto,
        # o que permite somar só o binário do aluno e isolar o algoritmo do I/O.
        callgrind_ok = _checar_callgrind()

        # Seleciona a escala de N adequada para a estratégia de medição disponível
        escala_ativa = TAMANHOS_ESCALA_INSTRUCOES if callgrind_ok else TAMANHOS_ESCALA_TIME
        estrategia = "callgrind (instruções do aluno)" if callgrind_ok else "wall_time_ns (fallback — Callgrind indisponível)"

        print(f"  -> [Malha 3] Parâmetro de escala: '{var_escala}' | Escala: {escala_ativa}")

        dados_coletados = {}  # acumula {N: métrica} para cada tamanho testado
        metrica_fonte = None  # registra qual método foi usado ("callgrind (Ir aluno)" ou "wall_time_ns")

        for N in escala_ativa:
            entrada_stdin = gerar_entrada_para_n(N)        # gera o stdin com N elementos
            valor, fonte = coletar_metrica(binario_saida, entrada_stdin)  # mede o custo

            if valor is not None:
                dados_coletados[N] = valor       # ponto válido — adiciona ao conjunto de dados
                if metrica_fonte is None:
                    metrica_fonte = fonte        # registra a fonte apenas na primeira medição válida

                unidade = "instr." if "callgrind" in (fonte or "") else "ns"
                print(f"     N={N:>7,}: {valor:>16,} {unidade}")
            else:
                # Ponto descartado: abaixo do limiar de ruído ou timeout
                print(f"     N={N:>7,}: abaixo do limiar de ruído ou timeout")

        # ── FASE 3: Verifica se há pontos suficientes para a regressão ────────────
        if len(dados_coletados) < 3:
            return {
                "status": "dados_insuficientes",
                "complexidade_inferida": "Indeterminada",
                "metrica_usada": metrica_fonte,
                "dados_coletados": dados_coletados,
                "detalhes": (
                    f"Apenas {len(dados_coletados)} de {len(escala_ativa)} pontos coletados "
                    "com sinal acima do limiar. Regressão requer mínimo de 3. "
                    f"Estratégia usada: {estrategia}. "
                    "Verifique se o Valgrind está instalado ou o timeout dos algoritmos "
                    "(a emulação do Callgrind é lenta para N grande)."
                )
            }

        # ── FASE 4: Regressão estatística — infere a curva Big-O ─────────────────
        # Passa os pontos coletados para a regressão que testa cada família de complexidade
        complexidade = inferir_big_o(dados_coletados, list(dados_coletados.keys()))
        print(f"  -> [Malha 3] Complexidade inferida: {complexidade}")

        return {
            "status": "sucesso",
            "complexidade_inferida": complexidade,
            "metrica_usada": metrica_fonte,
            "dados_coletados": dados_coletados,
            "detalhes": (
                f"Regressão sobre {len(dados_coletados)} pontos via '{metrica_fonte}'. "
                f"Tamanhos testados: {list(dados_coletados.keys())}"
            )
        }

    finally:
        # Garante a remoção do diretório temporário do binário nativo para não entulhar o /tmp
        shutil.rmtree(temp_dir, ignore_errors=True)