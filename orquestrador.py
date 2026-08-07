import os
import csv
import importlib.util

# Malha 1: AddressSanitizer + GDB (erros espaciais de memória)
from src.malha1_asan import executar_malha_1_asan

# Malha 2: Valgrind + vgdb (vícios semânticos: variáveis não inicializadas, leaks)
from src.malha2_valgrind import executar_malha_2_valgrind

# Parser unificado: filtra o log bruto antes de enviar ao LLM
from src.parser_logs import limpar_log_gdb

# Cliente do LLM local (Ollama) que retorna a classificação forense como JSON
from src.llm_client import classificar_erro

# Configuração central: caminhos, interruptor da Malha 3, etc. Ver src/config.py.
from src.config import (
    PASTA_CODIGOS,
    ARQUIVO_CSV_SAIDA,
    PASTA_ANOTADOS,
    MALHA_3_ATIVA,
)

# ── Malha 3: Perfilamento de complexidade (módulo exploratório) ───────────────
# O perfilador ainda precisa de fundamentação teorica para compor o pipeline,por isso consta na pasta "Trabalhos em Aberto"
# (fase exploratória), fora de src/. Por isso ele é carregado por caminho
# explícito via importlib, e não por um import de pacote comum.

# Import protegido: se o arquivo não existir ou faltar alguma dependência
# (numpy/scipy), a Malha 3 é apenas pulada — o pipeline de memória (Malhas 1 e 2)
# continua funcionando normalmente.
executar_malha_3_desempenho = None
try:
    _PERF_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "Trabalhos em Aberto", "perfilador_desempenho.py"
    )
    _spec = importlib.util.spec_from_file_location("perfilador_desempenho", _PERF_PATH)
    _perfilador = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_perfilador)
    executar_malha_3_desempenho = _perfilador.executar_malha_3_desempenho
    print("[Info] Malha 3 (perfilador) carregada de 'Trabalhos em Aberto'.")
except Exception as e:
    print(f"[Aviso] Malha 3 (perfilador) indisponível — pipeline seguirá sem ela. Motivo: {e}")

# PASTA_CODIGOS, ARQUIVO_CSV_SAIDA, PASTA_ANOTADOS e MALHA_3_ATIVA vêm de src/config.py.


def main():
    resultados_csv = []

    print("=== Iniciando Pipeline CodeBench (Modo Catálogo) ===")
    os.makedirs("./output", exist_ok=True)

    for nome_arquivo in os.listdir(PASTA_CODIGOS):
        if not nome_arquivo.endswith('.c'):
                ##(nome_arquivo == "teste_vetor_quicksort.c" 
                ##or nome_arquivo == "teste_selection_sort.c" 
                ##or nome_arquivo == "teste_busca_binaria.c" 
                ##or nome_arquivo == "teste_busca_sequencial.c"): */
            continue

        caminho_codigo = os.path.join(PASTA_CODIGOS, nome_arquivo)
        print(f"\n{'─' * 90}")
        print(f"[Analisando] {nome_arquivo}")

        # Campos preenchidos conforme o fluxo da cascata
        ferramenta_usada = "Nenhuma"
        log_bruto = None
        resultado_malha3 = None
        # categoria distingue erro de MEMÓRIA de erro de COMPILAÇÃO, para não rotular
        # uma falha do compilador como se fosse um bug de memória detectado pelo ASan.
        categoria_erro = "memoria"

        # ── MALHA 1: AddressSanitizer + GDB ──────────────────────────────────
        # Detecta infrações físicas/espaciais (buffer overflow, use-after-free) e
        # crashes por sinal (SIGSEGV etc.). Característica fail-fast: se detectado,
        # aborta e não executa Malha 2/3.
        resultado = executar_malha_1_asan(caminho_codigo)
        if resultado:
            tipo_m1 = resultado.get("tipo", "asan")
            if tipo_m1 == "compilacao":
                # NÃO é erro de memória: quem barrou foi o gcc, não o ASan/GDB.
                ferramenta_usada = "Compilador (gcc)"
                categoria_erro = "compilacao"
            elif tipo_m1 == "crash":
                # Crash cru (SIGSEGV etc.) que o GDB interceptou antes do relatório do ASan.
                ferramenta_usada = f"ASan+GDB (crash: {resultado.get('sinal', 'sinal')})"
            else:
                ferramenta_usada = "ASan+GDB"
            log_bruto = resultado["log"]

        else:
            # ── MALHA 2: Valgrind + vgdb ─────────────────────────────────────
            # Detecta vícios semânticos (variáveis não inicializadas, leaks).
            # Só roda se a Malha 1 passou limpa — arquitetura em cascata.
            resultado = executar_malha_2_valgrind(caminho_codigo)
            if resultado:
                ferramenta_usada = "Valgrind+vgdb"
                log_bruto = resultado["log"]

            else:
                # ── MALHA 3: Perfilamento de complexidade ────────────────────
                # Só executa se o código passou limpo nas malhas de memória —
                # o comportamento assintótico de código com UB é indefinido.
                if MALHA_3_ATIVA and executar_malha_3_desempenho is not None:
                    print("  -> Código sem erros de memória. Executando Malha 3 (perfilamento)...")
                    resultado_malha3 = executar_malha_3_desempenho(
                        caminho_codigo
                    )
                elif not MALHA_3_ATIVA:
                    print("  -> Código sem erros de memória. Malha 3 desativada (MALHA_3_ATIVA=False).")

        # ── REGISTRO NO CATÁLOGO ─────────────────────────────────────────────
        if log_bruto:
            # Caso 1: uma falha foi detectada (erro de memória, crash OU compilação).
            #print(f"  -> Falha detectada ({ferramenta_usada}). Extraindo contexto...")

           # print(f"  -> Log bruto ({len(log_bruto.splitlines())} linhas):\n{log_bruto}\n")
            log_limpo = limpar_log_gdb(log_bruto, nome_arquivo)
            print(f"  -> Log limpo ({len(log_limpo.splitlines())} linhas):\n{log_limpo}\n")

           
            with open(caminho_codigo, 'r', encoding='utf-8', errors='replace') as f:
                codigo_fonte = f.read()

            print(f"  -> Acionando IA Local para classificação forense...")
            # nome_arquivo é necessário para ancorar as anotações inline (// @@) nas
            # linhas exatas que a ferramenta reportou dentro do código do aluno.
            # log_bruto é passado para a EXTRAÇÃO das linhas rodar sobre o relatório
            # completo (todas as seções), sem depender do que o parser manteve.
            analise_ia = classificar_erro(log_limpo, codigo_fonte, nome_arquivo, log_bruto=log_bruto)

            # ── SAÍDA: código do aluno com as anotações inline (// @@) ───────────
            # Salva o código anotado como "<nome>_AnotacaoErro.c" (só quando houve
            # anotação de fato), mostrando NO código onde está o sintoma e a causa do erro.
            
            codigo_anotado = analise_ia.get("codigo_anotado", "")

            if codigo_anotado and "// @@" in codigo_anotado:
                pasta_anotados = PASTA_ANOTADOS               # vem do config central
                os.makedirs(pasta_anotados, exist_ok=True)
                base = os.path.splitext(nome_arquivo)[0]
                caminho_anotado = os.path.join(pasta_anotados, f"{base}_AnotacaoErro.c")
                with open(caminho_anotado, 'w', encoding='utf-8') as fa:
                    fa.write(codigo_anotado)
                print(f"  -> Código anotado salvo em: {caminho_anotado}")

            # A Malha 3 nunca roda quando há uma falha; a NOTA muda conforme a causa,
            # para o catálogo não dizer "erro de memória" quando foi o compilador.
            nota_malha3 = (
                "N/A (erro de compilação)"
                if categoria_erro == "compilacao"
                else "N/A (erro de memória detectado)"
            )

            resultados_csv.append({
                "Arquivo":         nome_arquivo,
                "Ferramenta":      ferramenta_usada,
                "Tipo Erro":       analise_ia.get("tipo_erro", "Desconhecido"),
                # CWE determinístico (do log da ferramenta) — padrão citável + checagem.
                "CWE ID":          analise_ia.get("cwe_id", "-"),
                "CWE Nome":        analise_ia.get("cwe_nome", "-"),
                # Linhas determinísticas (vindas da ferramenta, não da IA): sintoma e causa.
                "Linha Sintoma":   analise_ia.get("linha_sintoma", "-"),
                "Linha Causa":     analise_ia.get("linha_causa", "-"),
                "Variaveis":       analise_ia.get("variaveis_envolvidas", "-"),
                "Causa Raiz":      analise_ia.get("causa_raiz", "-"),
                "Diagnostico":     analise_ia.get("descricao_curta", "-"),
                # Linha do log que embasa o diagnóstico (âncora anti-alucinação da IA)
                "Evidencia Log":   "'" + analise_ia.get("evidencia_log", "-") + "'",
                "Complexidade":    nota_malha3,
                "Metrica_Malha3":  "-",
                "Status_Malha3":   "não executada",
        })

        elif resultado_malha3:
            # Caso 2: código limpo nas malhas de memória e Malha 3 executada.
            status = resultado_malha3["status"]

            if status == "sucesso":
                print(f"  -> Complexidade inferida: {resultado_malha3['complexidade_inferida']}")
            elif status == "nao_aplicavel":
                print("  -> Malha 3: entrada fixa detectada — complexidade N/A.")
            elif status == "dados_insuficientes":
                print("  -> Malha 3: dados insuficientes para a regressão.")
            else:
                print(f"  -> Malha 3: {status}.")

            resultados_csv.append({
                "Arquivo":         nome_arquivo,
                "Ferramenta":      "Nenhuma (passou limpo)",
                "Tipo Erro":       "-",
                "CWE ID":          "-",
                "CWE Nome":        "-",
                "Linha Sintoma":   "-",
                "Linha Causa":     "-",
                "Variaveis":       "-",
                "Causa Raiz":      "-",
                "Diagnostico":     "Sem erros de memória detectados.",
                "Evidencia Log":   "-",
                "Complexidade":    resultado_malha3["complexidade_inferida"],
                "Metrica_Malha3":  resultado_malha3.get("metrica_usada") or "-",
                "Status_Malha3":   status,
            })

        else:
            # Caso 3: código limpo, mas a Malha 3 não pôde ser executada
            # (perfilador indisponível — ex.: sem numpy/scipy no ambiente).
            print("  -> Código passou limpo nas malhas de memória (Malha 3 não executada).")
            resultados_csv.append({
                "Arquivo":         nome_arquivo,
                "Ferramenta":      "Nenhuma (passou limpo)",
                "Tipo Erro":       "-",
                "CWE ID":          "-",
                "CWE Nome":        "-",
                "Linha Sintoma":   "-",
                "Linha Causa":     "-",
                "Variaveis":       "-",
                "Causa Raiz":      "-",
                "Diagnostico":     "Sem erros de memória detectados.",
                "Evidencia Log":   "-",
                "Complexidade":    "N/A",
                "Metrica_Malha3":  "-",
                "Status_Malha3":   "não executada",
            })

    # ── GRAVAÇÃO DO RELATÓRIO CSV ─────────────────────────────────────────────
    if resultados_csv:
        chaves = resultados_csv[0].keys()
        with open(ARQUIVO_CSV_SAIDA, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=chaves)
            writer.writeheader()
            writer.writerows(resultados_csv)
        print(f"\n=== Sucesso! Catálogo salvo em: {ARQUIVO_CSV_SAIDA} ===")
    else:
        print("\n=== Nenhum resultado a registrar no CSV. ===")


if __name__ == "__main__":
    main()
