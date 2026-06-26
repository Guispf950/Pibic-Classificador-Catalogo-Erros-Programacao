def limpar_log_gdb(log_bruto, nome_arquivo):
    """
    Filtra o log bruto do GDB/ASan/Valgrind, removendo ruído técnico e
    preservando apenas as linhas relevantes para o feedback ao aluno.
    Retorna uma string com as linhas relevantes separadas por '\\n'.
    """

    # Divide o log em linhas individuais para processamento linha a linha
    linhas = log_bruto.split('\n')

    # Lista que vai acumular apenas as linhas consideradas relevantes
    log_limpo = []

    for linha in linhas:
        # Remove espaços e tabulações das bordas da linha para simplificar as comparações
        linha_strip = linha.strip()

        # --- FILTRO 1: GUILHOTINA — PARA A LEITURA COMPLETAMENTE ---
        # O mapa de "shadow bytes" é uma representação interna do ASan da memória
        # corrompida. É puro ruído técnico de dezenas de linhas hexadecimais.
        # Ao encontrar esse marcador, interrompemos o loop inteiro: tudo que
        # vem depois também é lixo, então não há razão para continuar iterando.
        if "Shadow bytes" in linha_strip or "Shadow byte legend" in linha_strip:
            break

        # --- FILTRO 2: ESCUDO ANTI-DUMP — PULA A LINHA E CONTINUA ---
        # Linhas com mais de 300 caracteres são quase sempre dumps hexadecimais
        # internos do GDB (registradores, memória bruta). São ilegíveis para o aluno
        # e irrelevantes para o diagnóstico. Pulamos sem adicionar ao log limpo.
        if len(linha_strip) > 300:
            continue

        # --- FILTRO 3: ALERTAS CRÍTICOS ---
        # ASan: "ERROR:" já cobre o cabeçalho, mas os tokens abaixo identificam o TIPO do erro
        # Valgrind: cobre erros de acesso, uso de não-inicializados, frees inválidos e vazamentos
        ALERTAS_CRITICOS = [
            # --- ASan ---
            "ERROR:",               # cabeçalho geral de qualquer erro do ASan/LeakSanitizer
            "heap-buffer-overflow", # leitura/escrita além dos limites de um bloco no heap
            "stack-buffer-overflow",# leitura/escrita além dos limites de variável local na pilha
            "use-after-free",       # acesso a memória já liberada com free()/delete
            "use-after-return",     # acesso a variável local após retorno da função
            "double-free",          # free() chamado duas vezes no mesmo ponteiro
            "SEGV",                 # segfault detectado e capturado pelo ASan
            # --- Valgrind ---
            "Conditional jump",     # desvio condicional baseado em valor não inicializado
            "definitely lost",      # vazamento confirmado: ponteiro perdido, bloco inacessível
            "indirectly lost",      # vazamento indireto: só acessível via outro bloco perdido
            "Invalid",              # leitura/escrita/free inválidos (Invalid read, Invalid write, Invalid free)
            "Mismatched free",      # new[] liberado com delete (ou vice-versa)
            "Uninitialized",        # uso de valor de memória não inicializada
        ]

        if any(alerta in linha_strip for alerta in ALERTAS_CRITICOS):
         log_limpo.append(linha_strip)

        # --- FILTRO 3.5: CONTEXTO DE LOCALIZAÇÃO DE MEMÓRIA ---
        # Captura linhas que descrevem ONDE na memória o erro ocorreu e qual bloco estava envolvido.
        # Essenciais para feedback de use-after-free e buffer overflow.
        elif (
            linha_strip.startswith("Address 0x")          # Valgrind: "Address 0x... is N bytes after..."
            or linha_strip.startswith("previously")        # ASan: "previously allocated by thread..."
            or linha_strip.startswith("allocated by")      # variação do ASan
            or linha_strip.startswith("freed by")          # ASan: onde o free() aconteceu (use-after-free)
            or linha_strip.startswith("allocation of size")# tamanho do bloco envolvido
        ):
            log_limpo.append(linha_strip)

            
        # --- FILTRO 4: CONTEXTO DO ACESSO DE MEMÓRIA ---
        # Linhas "READ of size N" e "WRITE of size N" indicam o tipo e tamanho
        # do acesso que causou o erro — informação essencial para entender a falha.
        elif "READ of size" in linha_strip or "WRITE of size" in linha_strip:
            log_limpo.append(linha_strip)

        # --- FILTRO 5: RASTREIO NO ARQUIVO DO ALUNO ---
        # Linhas do backtrace que mencionam o arquivo do aluno (ex: "aluno.c:42")
        # mostram exatamente onde no código-fonte o erro ocorreu.
        # Descartamos frames de bibliotecas do sistema (libc, libasan etc.).
        elif nome_arquivo in linha_strip:
            log_limpo.append(linha_strip)

        # --- FILTRO 6: VARIÁVEIS LOCAIS (ANTI-RUÍDO DE SISTEMA) ---
        # O comando "info locals" do GDB gera linhas no formato "variavel = valor".
        # Precisamos excluir:
        # - Linhas começando com "==" → prefixo de metadados do Valgrind/ASan
        # - Linhas começando com " " → continuações de valores multilinhas do GDB
        # - Linhas começando com "__" → variáveis internas geradas pelo compilador
        #   (ex: __PRETTY_FUNCTION__, __func__) que não fazem parte do código do aluno
        elif "=" in linha_strip and not linha_strip.startswith("==") and not linha_strip.startswith(" "):
            if not linha_strip.startswith("__"):  # ignora símbolos internos do compilador
                log_limpo.append(linha_strip)

    # Imprime métricas do filtro para rastreabilidade durante desenvolvimento/debug
    print(f"  -> Log bruto de {len(linhas)} linhas filtrado estruturalmente para {len(log_limpo)} linhas relevantes.\n")
    print("  -> Log Limpo:\n" + "\n".join(log_limpo) + "\n")

    # Reconstrói o log filtrado como string única separada por quebras de linha
    return '\n'.join(log_limpo)