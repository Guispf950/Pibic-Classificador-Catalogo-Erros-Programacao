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

    # Marcadores de RUÍDO DE SISTEMA: frames e variáveis da libc / do carregador
    # dinâmico (ld.so) / da glibc. NÃO são código do aluno. Quando o GDB tira um
    # backtrace fora do código do aluno (ex.: durante a inicialização, ou nas camadas
    # abaixo do main), ele despeja DEZENAS dessas linhas — foi o que inflou o log para
    # 200+ linhas inúteis. Qualquer linha que contenha um destes marcadores é descartada.

    #Isso deve ser refinado nas proximas versões. 
    RUIDO_SISTEMA = (
        "/usr/", "sysdeps", "/elf/", "dl-load", "dl-map", "dl-deps", "dl-catch",
        "dl-open", "dl-init", "libc-start", "libc.so", "ld-linux", "/nptl/", "/csu/",
        "<optimized out>", "__PRETTY_FUNCTION__", ".S:", "debuginfod", "auto-load",
        "valgrind-monitor", "(below main)", "__libc_", "_dl_",
    )

    # Estado: estamos atualmente DENTRO de um frame do código do aluno?
    # As variáveis locais ("var = valor") só interessam quando pertencem a uma função
    # do aluno. Sem esse controle, os locais dos frames da libc entrariam no log.
    frame_do_aluno = False

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

        # --- FILTRO 2.5: FRONTEIRA DE FRAME (#0, #1, ...) ---
        # Toda vez que o backtrace troca de frame, decidimos se é do aluno ou do sistema.
        # Isso é feito ANTES do filtro de ruído para que a fronteira SEMPRE seja atualizada
        # (mesmo que o frame seja da libc), mantendo o estado 'frame_do_aluno' correto.
        if len(linha_strip) >= 2 and linha_strip[0] == "#" and linha_strip[1].isdigit():
            frame_do_aluno = nome_arquivo in linha_strip
            if frame_do_aluno:
                log_limpo.append(linha_strip)   # mantém só os frames do código do aluno
            continue

        # --- FILTRO 2.6: RUÍDO DE SISTEMA — PULA A LINHA ---
        # Linhas de libc/ld.so (frames "at ./elf/...", locais "<optimized out>", etc.).
        if any(marcador in linha_strip for marcador in RUIDO_SISTEMA):
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
            "uninitialised",        # variação britânica do anterior (minúscula, meio de frase)
            "use-after-scope",      # ASan: uso de variável local após sair do escopo

            # --- ORIGEM / CAUSA RAIZ (linhas geradas pelas novas flags) ---
            # Estas linhas NÃO dizem o sintoma; dizem ONDE o erro NASCEU. Preservá-las é
            # o que permite separar "linha do sintoma" de "linha da causa raiz".
            "Uninitialised",        # Valgrind --track-origins: "Uninitialised value was created by..."
            "was created by",       # rótulo da origem do valor não inicializado (stack/heap)
            "Block was alloc'd",    # Valgrind --keep-stacktraces: onde o bloco liberado foi ALOCADO
            "a block of size",      # Valgrind: "Address 0x.. is N bytes inside a block of size M free'd"
            "declared at",          # Valgrind --read-var-info: nome da variável e linha de declaração
            "is located",           # ASan: "0x.. is located N bytes inside of.. region" / var na stack
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
            frame_do_aluno = True   # a partir daqui, os locais pertencem ao aluno
            log_limpo.append(linha_strip)

        # --- FILTRO 6: VARIÁVEIS LOCAIS (SÓ DENTRO DE FRAME DO ALUNO) ---
        # O comando "info locals"/"bt full" do GDB gera linhas "variavel = valor".
        # Só interessam as do CÓDIGO DO ALUNO — por isso exigimos 'frame_do_aluno'.
        # Sem esse gate, os locais dos frames da libc (dezenas por frame) entrariam
        # no log. Também excluímos:
        # - Linhas começando com "==" → prefixo de metadados do Valgrind/ASan
        # - Linhas começando com " " → continuações de valores multilinhas do GDB
        # - Linhas começando com "__" → variáveis internas geradas pelo compilador
        elif (
            frame_do_aluno
            and "=" in linha_strip
            and not linha_strip.startswith("==")
            and not linha_strip.startswith(" ")
            and not linha_strip.startswith("__")
        ):
            log_limpo.append(linha_strip)

    

    # Reconstrói o log filtrado como string única separada por quebras de linha
    return '\n'.join(log_limpo)