import os
import csv

# Malha 1: AddressSanitizer + GDB (erros espaciais de memória)
# Malha 2: Valgrind + vgdb (vícios semânticos: variáveis não inicializadas, leaks)
from src.ferramentas_analise_dinamica import executar_malha_1_asan, executar_malha_2_valgrind

# Malha 3: Execução nativa + perf stat + regressão estatística (Big-O)
from src.perfilador_desempenho import executar_malha_3_desempenho

# Parser unificado: filtra o log bruto antes de enviar ao LLM
from src.parser_logs import limpar_log_gdb

# Cliente do LLM local (Ollama) que retorna a classificação forense como JSON
from src.llm_client import classificar_erro

# ── Configurações do pipeline ────────────────────────────────────────────────
PASTA_CODIGOS = "./codigos_alunos"
ARQUIVO_CSV_SAIDA = "./output/catalogo_erros_codebench.csv"


def main():
    resultados_csv = []

    print("=== Iniciando Pipeline CodeBench (Modo Catálogo) ===")
    os.makedirs("./output", exist_ok=True)

    for nome_arquivo in os.listdir(PASTA_CODIGOS):
        if not nome_arquivo.endswith('.c'):
            continue

        caminho_codigo = os.path.join(PASTA_CODIGOS, nome_arquivo)
        print(f"\n{'─' * 90}")
        print(f"[Analisando] {nome_arquivo}")

        # Campos que serão preenchidos conforme o fluxo da cascata
        ferramenta_usada = "Nenhuma"
        log_bruto = None
        resultado_malha3 = None

        # ── MALHA 1: AddressSanitizer + GDB ──────────────────────────────────
        # Detecta infrações físicas/espaciais (buffer overflow, use-after-free).
        # Característica fail-fast: se detectado, aborta e não executa Malha 2/3.
        resultado = executar_malha_1_asan(caminho_codigo)
        if resultado:
            ferramenta_usada = "ASan+GDB"
            log_bruto = resultado["log"]

        else:
            # ── MALHA 2: Valgrind + vgdb ─────────────────────────────────────
            # Detecta vícios semânticos (variáveis não inicializadas, leaks).
            # Só roda se Malha 1 passou limpa — mesma arquitetura de cascata.
            resultado = executar_malha_2_valgrind(caminho_codigo)
            if resultado:
                ferramenta_usada = "Valgrind+vgdb"
                log_bruto = resultado["log"]

            else:
                # ── MALHA 3: Perfilamento Algorítmico ────────────────────────
                # Só executa se o código passou limpo nas malhas de memória.
                # Razão arquitetural: não faz sentido auditar eficiência de um
                # algoritmo que viola a integridade da memória — o comportamento
                # assintótico de código com UB é tecnicamente indefinido.
                print(f"  -> Código sem erros de memória. Executando Malha 3 (perfilamento)...")
                resultado_malha3 = executar_malha_3_desempenho(
                    caminho_codigo,
                    binario_saida="./bin_nativo"
                )

        # ── ETAPA DE CLASSIFICAÇÃO POR IA ────────────────────────────────────
        if log_bruto:
            print(f"  -> Falha detectada ({ferramenta_usada}). Extraindo contexto...")
            log_limpo = limpar_log_gdb(log_bruto, nome_arquivo)

            with open(caminho_codigo, 'r', encoding='utf-8', errors='replace') as f:
                codigo_fonte = f.read()

            print(f"  -> Acionando IA Local para classificação forense...")
            analise_ia = classificar_erro(log_limpo, codigo_fonte)

            resultados_csv.append({
                "Arquivo":         nome_arquivo,
                "Ferramenta":      ferramenta_usada,
                "Tipo Erro":       analise_ia.get("tipo_erro", "Desconhecido"),
                "Linha":           analise_ia.get("linha_ocorrencia", "-"),
                "Variaveis":       analise_ia.get("variaveis_envolvidas", "-"),
                "Causa Raiz":      analise_ia.get("causa_raiz", "-"),
                "Diagnostico":     analise_ia.get("descricao_curta", "-"),
                # Malha 3 não roda quando há erro de memória (arquitetura em cascata)
                "Complexidade":    "N/A (erro de memória detectado)",
                "Metrica_Perf":    "-",
                "Status_Malha3":   "não executada",
            })

        elif resultado_malha3:
            # Código passou limpo nas malhas de memória: registra resultado da Malha 3
            status = resultado_malha3["status"]

            if status == "sucesso":
                print(f"  -> Complexidade inferida: {resultado_malha3['complexidade_inferida']}")
            elif status == "nao_aplicavel":
                print(f"  -> Malha 3: entrada fixa detectada — análise de complexidade N/A.")
            elif status == "dados_insuficientes":
                print(f"  -> Malha 3: dados insuficientes para regressão.")

            resultados_csv.append({
                "Arquivo":         nome_arquivo,
                "Ferramenta":      "Nenhuma (passou limpo)",
                "Tipo Erro":       "-",
                "Linha":           "-",
                "Variaveis":       "-",
                "Causa Raiz":      "-",
                "Diagnostico":     "Sem erros de memória detectados.",
                "Complexidade":    resultado_malha3["complexidade_inferida"],
                "Metrica_Perf":    resultado_malha3.get("metrica_usada") or "-",
                "Status_Malha3":   status,
            })

        else:
            print("  -> Código passou limpo nas auditorias de memória (Malha 3 não executada).")

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
