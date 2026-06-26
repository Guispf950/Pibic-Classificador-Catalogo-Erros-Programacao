import os   # Para navegar no sistema de arquivos (listar pastas, criar diretórios, montar caminhos)
import csv  # Para gravar o relatório final no formato CSV de forma estruturada

# Importa as duas malhas de análise dinâmica: ASan+GDB (Malha 1) e Valgrind+vgdb (Malha 2)
from src.ferramentas_analise_dinamica import executar_malha_1_asan, executar_malha_2_valgrind

# Importa o parser responsável por limpar/normalizar o log bruto antes de enviar à IA
from src.parser_logs import limpar_log_gdb

# Importa o cliente do LLM local que classifica o erro e retorna um dicionário estruturado
from src.llm_client import classificar_erro

# Diretório onde estão os arquivos .c dos alunos a serem analisados
PASTA_CODIGOS = "./codigos_alunos"

# Caminho do arquivo CSV que será gerado ao final com todos os erros catalogados
ARQUIVO_CSV_SAIDA = "./output/catalogo_erros_codebench.csv"


def main():
    resultados_csv = []  # Lista que acumula um dicionário por arquivo analisado com erro

    print("=== Iniciando Pipeline CodeBench (Modo Catálogo) ===")

    # Cria a pasta ./output se ainda não existir; exist_ok=True evita erro se já existir
    os.makedirs("./output", exist_ok=True)

    # Percorre todos os arquivos dentro da pasta de códigos dos alunos
    for nome_arquivo in os.listdir(PASTA_CODIGOS):

        # Filtra: ignora qualquer arquivo que não seja código-fonte C
        if not nome_arquivo.endswith('.c'):
            continue

        # Monta o caminho absoluto/relativo completo do arquivo para passar às ferramentas
        caminho_codigo = os.path.join(PASTA_CODIGOS, nome_arquivo)

        print(f"--------------------------------------------------------------------------------------------------")
        print(f"\n[Analisando] {nome_arquivo}...")

        ferramenta_usada = "Nenhuma"  # Registra qual ferramenta detectou o erro (para o CSV)
        log_bruto = None              # Guarda o log bruto retornado pela ferramenta; None = sem erro ainda

        # ── MALHA 1: AddressSanitizer + GDB ──────────────────────────────────────────
        # Compila e executa o código instrumentado com ASan. Se houver falha de memória
        # (buffer overflow, use-after-free, etc.), retorna um dict com a chave "log".
        resultado = executar_malha_1_asan(caminho_codigo)

        if resultado:
            # Malha 1 capturou um erro: registra a ferramenta e extrai o log bruto
            ferramenta_usada = "ASan+GDB"
            log_bruto = resultado["log"]
        else:
            # ── MALHA 2: Valgrind + vgdb ─────────────────────────────────────────────
            # Código passou limpo no ASan; tenta uma segunda auditoria com Valgrind,
            # que detecta erros mais sutis (leituras inválidas, memória não inicializada, etc.)
            resultado = executar_malha_2_valgrind(caminho_codigo)

            if resultado:
                # Malha 2 capturou um erro: registra a ferramenta e extrai o log bruto
                ferramenta_usada = "Valgrind+vgdb"
                log_bruto = resultado["log"]

        # ── ETAPA 3: Processamento do log e classificação por IA ─────────────────────
        # ── ETAPA 3: Processamento do log e classificação por IA ─────────────────────
        if log_bruto:
            print(f"  -> Falha detectada ({ferramenta_usada}). Extraindo contexto...")
            log_limpo = limpar_log_gdb(log_bruto, nome_arquivo)

            # Lê o código-fonte do aluno para enviar junto com o log à IA.
            # Com o código em mãos, o modelo consegue correlacionar a linha do erro
            # com a declaração real das variáveis, tipos e contexto ao redor —
            # em vez de inferir apenas pelo backtrace do depurador.
            # errors='replace' substitui bytes inválidos pelo caractere '?' em vez de quebrar.
            # Necessário porque arquivos .c de alunos podem ter comentários com acentos
            # salvos em encodings diferentes de UTF-8 (ex: latin-1, cp1252).
            with open(caminho_codigo, 'r', encoding='utf-8', errors='replace') as f:
                codigo_fonte = f.read()

            print(f"  -> Acionando IA Local para classificação forense...")
            analise_ia = classificar_erro(log_limpo, codigo_fonte)  # <-- passa o código

            # Constrói o registro deste arquivo para o CSV.
            # .get() com valor padrão garante que campos ausentes na resposta da IA não quebrem o pipeline.
            resultados_csv.append({
                "Arquivo":     nome_arquivo,
                "Ferramenta":  ferramenta_usada,
                "Tipo Erro":   analise_ia.get("tipo_erro", "Desconhecido"),
                "Linha":       analise_ia.get("linha_ocorrencia", "-"),
                "Variaveis":   analise_ia.get("variaveis_envolvidas", "-"),
                "Diagnostico": analise_ia.get("descricao_curta", "-")
            })
        else:
            # Nenhuma das duas malhas detectou falha: código considerado limpo nesta auditoria
            print("  -> Código passou limpo nas auditorias de memória.")

    # ── ETAPA 4: Gravação do relatório CSV ───────────────────────────────────────────
    if resultados_csv:  # Só grava se ao menos um erro foi encontrado durante o pipeline

        # Extrai os nomes das colunas do primeiro registro (todos os dicts têm as mesmas chaves)
        chaves = resultados_csv[0].keys()

        # Abre (ou cria) o CSV de saída em modo escrita com encoding UTF-8
        # newline='' é obrigatório com csv.DictWriter para evitar linhas em branco no Windows
        with open(ARQUIVO_CSV_SAIDA, 'w', newline='', encoding='utf-8') as f:

            # DictWriter mapeia automaticamente cada chave do dicionário para a coluna correta
            writer = csv.DictWriter(f, fieldnames=chaves)

            writer.writeheader()       # Escreve a linha de cabeçalho com os nomes das colunas
            writer.writerows(resultados_csv)  # Escreve todas as linhas de dados de uma vez

        print(f"\n=== Sucesso! Catálogo salvo em: {ARQUIVO_CSV_SAIDA} ===")


# Ponto de entrada do script: garante que main() só é chamada quando executado diretamente,
# não quando o módulo é importado por outro arquivo Python
if __name__ == "__main__":
    main()