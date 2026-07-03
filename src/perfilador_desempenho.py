"""
Malha 3: Perfilamento Algorítmico e Inferência de Complexidade Assintótica
=========================================================================

Implementa o Perfilamento Algorítmico conforme descrito na arquitetura proposta.

IDEIA CENTRAL:
    Em vez de medir o tempo de parede (que varia com a carga do servidor),
    submetemos o binário a entradas de tamanho crescente (N=10, 100, 1000...)
    e contamos quantas instruções de máquina a CPU executou para cada N.
    Com esses pontos, uma regressão estatística infere a curva Big-O.

DOIS CENÁRIOS POSSÍVEIS:
    Cenário A — Exercício com template CodeBench (ex: "leia N e ordene N números"):
        O orquestrador injeta N pelo stdin e varia o tamanho livremente.
        → Análise de complexidade completa é possível.

    Cenário B — Exercício de entrada fixa (ex: "some 3 números"):
        N não pode ser variado sem reescrever o código do aluno.
        → Análise marcada como N/A com justificativa.
"""

import re
import subprocess
import warnings

import numpy as np
from scipy.optimize import curve_fit


# ══════════════════════════════════════════════════════════════════════════════
# PRÉ-CHECK: DISPONIBILIDADE DO PERF
# ══════════════════════════════════════════════════════════════════════════════

def _perf_disponivel():
    """
    Verifica em <3s se `perf stat` está funcional neste ambiente.

    Por que não confiar no FileNotFoundError do coletar_instrucoes_perf?
        Em WSL e alguns ambientes de CI, o binário `perf` existe mas trava
        ao tentar acessar hardware performance counters (PEBS, PMU) que o
        hypervisor não expõe. Em vez de falhar rápido com um erro, o processo
        fica suspenso aguardando o kernel — até o timeout de 30s ser atingido.
        Com 7 tamanhos de escala + 1 sonda, isso resulta em 8 × 30s = ~4min
        de travamento antes do fallback de tempo ser ativado.

    Solução: rodar `perf stat -- true` (binário que encerra instantaneamente)
        com timeout curto. Se responder em <3s, perf está funcional.
        Se travar ou falhar, assume indisponível e vai direto para o fallback.
    """
    try:
        resultado = subprocess.run(
            ["perf", "stat", "--", "true"],
            capture_output=True,
            text=True,
            timeout=3          # 3s é mais que suficiente para `true` terminar
        )
        # Verifica se a saída contém o marcador de sucesso do perf
        return "Performance counter stats" in resultado.stderr
    except Exception:
        return False


# Cache do resultado: executado uma vez por processo, evita re-check a cada medição
_PERF_DISPONIVEL: bool | None = None

def _checar_perf():
    """Retorna (e cacheia) a disponibilidade do perf para este processo."""
    global _PERF_DISPONIVEL
    if _PERF_DISPONIVEL is None:
        _PERF_DISPONIVEL = _perf_disponivel()
        status = "disponível" if _PERF_DISPONIVEL else "indisponível — usando fallback de tempo"
        print(f"  -> [Malha 3] perf stat: {status}")
    return _PERF_DISPONIVEL


# ══════════════════════════════════════════════════════════════════════════════
# BLOCO 1 — DETECÇÃO DO MODO DE ENTRADA
# ══════════════════════════════════════════════════════════════════════════════

def detectar_parametro_escala(codigo_fonte):
    """
    Lê o código C do aluno e determina se ele possui um parâmetro de tamanho N
    que o orquestrador pode controlar via stdin (Cenário A) ou não (Cenário B).

    A detecção funciona em duas etapas:
      1. Encontra um scanf que lê EXATAMENTE um inteiro: scanf("%d", &var)
         (exclui formatos compostos como "%d %d" que indicam entradas fixas)
      2. Confirma que essa variável controla um laço ou uma alocação dinâmica,
         ou seja, que ela realmente representa o "tamanho" do problema.

    Retorna o nome da variável de escala (ex: "n", "k") ou None se for Cenário B.
    """

    # Remove comentários de linha (//) e de bloco (/* */) antes de analisar.
    # Sem isso, um scanf comentado poderia ser detectado como parâmetro de escala.
    codigo = re.sub(r'//.*', '', codigo_fonte)
    codigo = re.sub(r'/\*.*?\*/', '', codigo, flags=re.DOTALL)

    # Busca scanf que lê EXATAMENTE um inteiro ("%d"), sem outros especificadores.
    # O grupo(2) captura o nome da variável (ex: "k" em scanf("%d", &k)).
    # Exemplos aceitos: scanf("%d", &n)  → detectado
    # Exemplos rejeitados: scanf("%d %d", &a, &b)  → ignorado (entrada composta)
    matches = list(re.finditer(
        r'scanf\s*\(\s*"(%d)"\s*,\s*&\s*(\w+)\s*\)',
        codigo
    ))

    for m in matches:
        var = m.group(2)  # nome da variável lida pelo scanf (ex: "n", "k", "tam")

        # Verifica se a variável realmente representa o "tamanho" do problema,
        # checando se ela aparece como limite de laço ou tamanho de alocação.
        usada_como_tamanho = (
            # for(int i = 0; i < var; ...) — var como limite superior de for
            re.search(rf'for\s*\([^;]*;\s*[^;]*{re.escape(var)}[^;]*;', codigo)
            # while(i < var) ou while(var > 0) — var como condição de parada
            or re.search(rf'while\s*\([^)]*{re.escape(var)}', codigo)
            # malloc(var * sizeof(...)) — var como quantidade de elementos alocados
            or re.search(rf'malloc\s*\([^)]*{re.escape(var)}', codigo)
            # calloc(var, sizeof(...)) — mesmo caso acima com calloc
            or re.search(rf'calloc\s*\([^)]*{re.escape(var)}', codigo)
            # int arr[var] — VLA (Vetor de Tamanho Variável) usando var como tamanho
            or re.search(rf'\[\s*{re.escape(var)}\s*\]', codigo)
        )

        # Se a variável controla tamanho, este é o parâmetro de escala do Cenário A
        if usada_como_tamanho:
            return var

    # Nenhuma variável de escala encontrada → Cenário B (entrada fixa)
    return None


# ══════════════════════════════════════════════════════════════════════════════
# BLOCO 2 — GERAÇÃO DE ENTRADAS ESCALONADAS
# ══════════════════════════════════════════════════════════════════════════════

def gerar_entrada_para_n(N, formato="N_ESPACO_VALORES"):
    """
    Gera a string que será enviada pelo stdin do programa para um dado N.

    Padrão CodeBench mais comum:
        Linha 1 → o número N (tamanho da entrada)
        Linha 2 → N inteiros separados por espaço (os dados a processar)

    Compatível com scanf("%d", &arr[i]) tanto em loop (lê um por chamada)
    quanto em linha única — o scanf com %d ignora whitespace automaticamente.
    """
    if formato == "N_ESPACO_VALORES":
        # Gera N inteiros sequenciais (1, 2, 3, ..., N) separados por espaço.
        # Usar valores crescentes em vez de constantes evita que o branch predictor
        # da CPU otimize artificialmente o código do aluno durante a medição.
        valores = " ".join(str(i + 1) for i in range(N))
        return f"{N}\n{valores}\n"  # ex: "5\n1 2 3 4 5\n"

    elif formato == "N_LINHA_POR_LINHA":
        # Variante onde cada valor ocupa uma linha separada (alguns exercícios pedem isso)
        valores = "\n".join(str(i + 1) for i in range(N))
        return f"{N}\n{valores}\n"  # ex: "5\n1\n2\n3\n4\n5\n"

    # Fallback: envia apenas N, sem dados adicionais (para programas que só leem o tamanho)
    return f"{N}\n"


# ══════════════════════════════════════════════════════════════════════════════
# BLOCO 3 — COLETA DE MÉTRICAS DE DESEMPENHO
# ══════════════════════════════════════════════════════════════════════════════

def coletar_instrucoes_perf(binario, stdin_input, timeout=30):
    """
    Executa o binário com `perf stat` e retorna o total de instruções de máquina
    executadas pela CPU (Hardware Performance Counter — HPC).

    Por que instruções e não tempo?
        Instruções são determinísticas: o mesmo código com a mesma entrada
        executa sempre o mesmo número de instruções, independente da carga
        do servidor. O tempo de parede varia com o scheduler do SO.

    Retorna o número de instruções (int) ou None se perf não estiver disponível.
    """
    # Curto-circuito: se o pre-check já sabe que perf não está disponível,
    # não tenta — evita o travamento de 30s que ocorre em WSL/CI sem PMU.
    if not _checar_perf():
        return None

    try:
        resultado = subprocess.run(
            # "instructions:u" — conta apenas instruções do espaço do usuário,
            # excluindo syscalls do kernel (que seriam ruído para a análise do algoritmo)
            ["perf", "stat", "-e", "instructions:u", "--", binario],
            input=stdin_input,       # injeta a entrada gerada pelo gerar_entrada_para_n()
            capture_output=True,     # captura stdout e stderr sem exibir no terminal
            text=True,
            timeout=timeout
        )

        # O perf stat SEMPRE escreve suas métricas no stderr (por design da ferramenta),
        # mesmo que o programa medido escreva no stdout
        saida = resultado.stderr

        # Extrai o número de instruções da linha "1,234,567,890  instructions:u"
        # O padrão aceita tanto vírgula (en_US) quanto ponto (pt_BR) como separador de milhar
        match = re.search(r'([\d,\.]+)\s+instructions', saida)
        if match:
            # Remove separadores de milhar e converte para int
            raw = match.group(1).replace(',', '').replace('.', '')
            return int(raw)

    except FileNotFoundError:
        pass  # `perf` não está instalado no sistema — cai para o fallback de tempo
    except subprocess.TimeoutExpired:
        pass  # programa travou neste N — descarta o ponto e continua
    except (ValueError, AttributeError):
        pass  # parsing do número falhou — descarta o ponto
    except Exception:
        pass  # qualquer outro erro inesperado — descarta silenciosamente

    return None  # sinaliza que o perf não está disponível ou falhou


# Piso de ruído do fallback de tempo: medições abaixo de 2ms estão no overhead
# de fork + exec + I/O do subprocess — não refletem o algoritmo em si.
# Pontos abaixo deste limiar são descartados antes da regressão.
LIMIAR_RUIDO_NS = 2_000_000  # 2 ms em nanosegundos


def coletar_tempo_parede_ns(binario, stdin_input, n_medicoes=5, timeout=15):
    """
    Fallback quando `perf stat` não está disponível.

    Mede o tempo de execução usando perf_counter_ns() (resolução de nanosegundos)
    e retorna a MEDIANA de 9 medições para reduzir o jitter do scheduler do SO.

    Por que mediana e não média?
        A média é sensível a outliers (picos de latência do SO).
        A mediana representa a execução "típica" sem ser distorcida por picos.

    Por que 9 medições?
        Número ímpar facilita o cálculo da mediana. Com 9 amostras, o erro
        estatístico já é pequeno o suficiente para a regressão Big-O.

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

    1ª opção: perf stat (HPC) — instruções reais da CPU, determinístico
    2ª opção: mediana de tempo de parede em ns — usado quando perf não está disponível

    Se o tempo medido for menor que LIMIAR_RUIDO_NS (2ms), descarta o ponto:
    ele está no piso de overhead do subprocess, não no algoritmo.

    Retorna (valor, fonte) onde fonte identifica qual método foi usado,
    ou (None, None) se ambos falharem ou o valor estiver abaixo do limiar.
    """
    # Tenta primeiro o método de referência (HPC via perf)
    instrucoes = coletar_instrucoes_perf(binario, stdin_input)
    if instrucoes is not None:
        return instrucoes, "perf_stat"  # retorna imediatamente com o melhor método

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
    x_data = np.array(ns_validos, dtype=float)                            # valores de N (eixo X)
    y_data = np.array([resultados[int(n)] for n in ns_validos], dtype=float)  # métricas (eixo Y)

    # Normaliza Y para o intervalo [0, 1] dividindo pelo máximo.
    # Isso garante estabilidade numérica no curve_fit — sem normalização,
    # números na escala de bilhões (instruções de CPU) causam overflow no solver.
    y_max = np.max(y_data)
    y_norm = y_data / y_max if y_max > 0 else y_data

    # Famílias assintóticas testadas — cobrindo os casos típicos de CS1/CS2
    # Cada lambda é f(x, c) = c * g(x), onde c é o parâmetro livre ajustado
    modelos = {
        "O(1) - Constante":        lambda x, c: c * np.ones_like(x),              # custo fixo, independente de N
        "O(log N) - Logarítmica":  lambda x, c: c * np.log2(np.maximum(x, 1.0)), # busca binária, árvores balanceadas
        "O(N) - Linear":           lambda x, c: c * x,                            # varredura simples de array
        "O(N log N) - Log-Linear": lambda x, c: c * x * np.log2(np.maximum(x, 1.0)),  # mergesort, quicksort médio
        "O(N²) - Quadrática":      lambda x, c: c * (x ** 2),                    # bubble sort, seleção, inserção
        "O(N³) - Cúbica":          lambda x, c: c * (x ** 3),                    # multiplicação de matrizes ingênua
        "O(2^N) - Exponencial":    lambda x, c: c * (2.0 ** np.minimum(x, 60.0)), # recursão sem memoização (ex: fibonacci ingênuo)
        # np.minimum(..., 60) evita overflow de float para N grande
    }

    melhor_modelo = "Indeterminada"
    melhor_r2 = -float('inf')  # inicializa com menos infinito para que qualquer R² seja melhor

    warnings.filterwarnings("ignore")  # suprime avisos de convergência do curve_fit durante a busca
    for nome, func in modelos.items():
        try:
            # Ajusta os parâmetros da função ao conjunto de dados.
            # p0=[1.0] é o chute inicial para o parâmetro c — 1.0 é seguro para dados normalizados.
            # maxfev=20000 aumenta o limite de iterações para curvas difíceis de convergir (ex: exponencial).
            popt, _ = curve_fit(func, x_data, y_norm, p0=[1.0], maxfev=20000)

            # Calcula os valores preditos pelo modelo com o parâmetro c ajustado
            y_pred = func(x_data, *popt)

            # Calcula R² = 1 - (SS_res / SS_tot)
            ss_res = np.sum((y_norm - y_pred) ** 2)  # soma dos quadrados dos resíduos (erro do modelo)
            ss_tot = np.sum((y_norm - np.mean(y_norm)) ** 2)  # variância total dos dados

            # Se ss_tot == 0, todos os pontos têm o mesmo valor → R² = 1 (ajuste perfeito por definição)
            r2 = 1.0 - (ss_res / ss_tot) if ss_tot != 0 else 1.0

            # Atualiza o melhor modelo se este R² for o maior encontrado até agora
            if r2 > melhor_r2:
                melhor_r2 = r2
                melhor_modelo = nome

        except Exception:
            continue  # modelo não convergiu para estes dados — ignora e testa o próximo

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

# Escala preferencial quando perf stat está disponível.
# Começa em N=10 porque o perf conta instruções absolutas — sinal mensurável desde entradas pequenas.
TAMANHOS_ESCALA_PERF = [10, 50, 100, 500, 1000, 5000, 10000]

# Escala usada no fallback de tempo de parede.
# Valores menores para que a análise complete em segundos, não minutos.
# N=100..4000 já gera sinal suficiente acima do limiar de 2ms para algoritmos O(N log N) ou piores.
TAMANHOS_ESCALA_TIME = [100, 200, 1_000, 2_000, 4_000]

# Alias de compatibilidade — mantido caso algum módulo importe TAMANHOS_ESCALA diretamente
TAMANHOS_ESCALA = TAMANHOS_ESCALA_PERF


def executar_malha_3_desempenho(caminho_codigo, binario_saida="./bin_nativo"):
    """
    Orquestra as três fases do perfilamento algorítmico:
      1. Compila o código sem instrumentação (execução pura, sem overhead de ASan/Valgrind)
      2. Detecta o cenário de entrada e coleta métricas para entradas escalonadas
      3. Infere a complexidade Big-O por regressão estatística

    Retorna um dict com:
        status               → "sucesso" | "nao_aplicavel" | "dados_insuficientes" | "erro_compilacao"
        complexidade_inferida→ string Big-O (ex: "O(N²)") ou "N/A"
        metrica_usada        → "perf_stat" | "wall_time_ns (fallback)" | None
        dados_coletados      → {N: métrica} — pontos usados na regressão
        detalhes             → mensagem explicativa para log e debug
    """

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
    # _checar_perf() faz um pre-check de 3s UMA VEZ e cacheia o resultado.
    # Isso evita o travamento de 30s×8 que ocorria em WSL sem PMU disponível.
    perf_ok = _checar_perf()

    # Seleciona a escala de N adequada para a estratégia de medição disponível
    escala_ativa = TAMANHOS_ESCALA_PERF if perf_ok else TAMANHOS_ESCALA_TIME
    estrategia = "perf stat (HPC)" if perf_ok else "wall_time_ns (fallback — perf indisponível)"

    print(f"  -> [Malha 3] Parâmetro de escala: '{var_escala}' | Escala: {escala_ativa}")

    dados_coletados = {}  # acumula {N: métrica} para cada tamanho testado
    metrica_fonte = None  # registra qual método foi usado ("perf_stat" ou "wall_time_ns")

    for N in escala_ativa:
        entrada_stdin = gerar_entrada_para_n(N)        # gera o stdin com N elementos
        valor, fonte = coletar_metrica(binario_saida, entrada_stdin)  # mede o custo

        if valor is not None:
            dados_coletados[N] = valor       # ponto válido — adiciona ao conjunto de dados
            if metrica_fonte is None:
                metrica_fonte = fonte        # registra a fonte apenas na primeira medição válida

            unidade = "instr." if "perf" in (fonte or "") else "ns"
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
                "Verifique perf_event_paranoid no servidor ou timeout dos algoritmos."
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