def limpar_log_gdb(log_bruto, nome_arquivo):
    """
    Filtra o log bruto do GDB/ASan/Valgrind, removendo ruído técnico e preservando apenas as
    linhas relevantes para o feedback ao aluno. Retorna as linhas relevantes unidas por '\\n'.
    """

    linhas = log_bruto.split('\n')
    log_limpo = []

    # Marcadores de RUÍDO DE SISTEMA: frames/variáveis da libc, do carregador dinâmico (ld.so)
    # e da glibc — não são código do aluno. Um backtrace fora do código do aluno despeja dezenas
    # dessas linhas (é o que inflava o log para 200+ linhas). Qualquer linha que os contenha é
    # descartada.
    # Isso deve ser refinado nas próximas versões.
    RUIDO_SISTEMA = (
        "/usr/", "sysdeps", "/elf/", "dl-load", "dl-map", "dl-deps", "dl-catch",
        "dl-open", "dl-init", "libc-start", "libc.so", "ld-linux", "/nptl/", "/csu/",
        "<optimized out>", "__PRETTY_FUNCTION__", ".S:", "debuginfod", "auto-load",
        "valgrind-monitor", "(below main)", "__libc_", "_dl_",
    )

    # Estado: estamos dentro de um frame do código do aluno? As variáveis locais ("var = valor")
    # só interessam quando pertencem a uma função do aluno.
    frame_do_aluno = False

    for linha in linhas:
        linha_strip = linha.strip()

        # FILTRO 1 (guilhotina): o mapa de "shadow bytes" do ASan é puro ruído hexadecimal;
        # tudo depois dele também é lixo, então interrompe o loop inteiro.
        if "Shadow bytes" in linha_strip or "Shadow byte legend" in linha_strip:
            break

        # FILTRO 2 (anti-dump): linhas > 300 chars são quase sempre dumps hexadecimais do GDB
        # (registradores, memória bruta) — ilegíveis e irrelevantes.
        if len(linha_strip) > 300:
            continue

        # FILTRO 2.5 (fronteira de frame #0, #1, ...): a cada troca de frame decide se é do aluno
        # ou do sistema. Feito ANTES do filtro de ruído para manter 'frame_do_aluno' sempre correto.
        if len(linha_strip) >= 2 and linha_strip[0] == "#" and linha_strip[1].isdigit():
            frame_do_aluno = nome_arquivo in linha_strip
            if frame_do_aluno:
                log_limpo.append(linha_strip)   # mantém só os frames do código do aluno
            continue

        # FILTRO 2.6 (ruído de sistema): frames/locais de libc e ld.so.
        if any(marcador in linha_strip for marcador in RUIDO_SISTEMA):
            continue

        # FILTRO 3 (alertas críticos): tokens que identificam o TIPO do erro no ASan e no Valgrind
        # (acessos inválidos, não-inicializados, frees inválidos, vazamentos). As linhas de
        # ORIGEM/CAUSA (final da lista) dizem ONDE o erro nasceu — preservá-las é o que permite
        # separar a linha do sintoma da linha da causa raiz.
        ALERTAS_CRITICOS = [
            # ASan
            "ERROR:", "heap-buffer-overflow", "stack-buffer-overflow", "use-after-free",
            "use-after-return", "double-free", "SEGV",
            # Valgrind
            "Conditional jump", "definitely lost", "indirectly lost", "Invalid",
            "Mismatched free", "Uninitialized", "uninitialised", "use-after-scope",
            # Origem / causa raiz (linhas das flags --track-origins / --keep-stacktraces)
            "Uninitialised", "was created by", "Block was alloc'd", "a block of size",
            "declared at", "is located",
        ]

        if any(alerta in linha_strip for alerta in ALERTAS_CRITICOS):
         log_limpo.append(linha_strip)

        # FILTRO 3.5 (localização de memória): onde na memória o erro ocorreu e qual bloco estava
        # envolvido — essencial para use-after-free e buffer overflow.
        elif (
            linha_strip.startswith("Address 0x")
            or linha_strip.startswith("previously")
            or linha_strip.startswith("allocated by")
            or linha_strip.startswith("freed by")
            or linha_strip.startswith("allocation of size")
        ):
            log_limpo.append(linha_strip)

        # FILTRO 4 (contexto do acesso): "READ/WRITE of size N" — tipo e tamanho do acesso que
        # causou o erro.
        elif "READ of size" in linha_strip or "WRITE of size" in linha_strip:
            log_limpo.append(linha_strip)

        # FILTRO 5 (rastreio no arquivo do aluno): linhas do backtrace que citam o arquivo
        # (ex.: "aluno.c:42") mostram onde no fonte o erro ocorreu.
        elif nome_arquivo in linha_strip:
            frame_do_aluno = True   # a partir daqui, os locais pertencem ao aluno
            log_limpo.append(linha_strip)

        # FILTRO 6 (variáveis locais, só dentro de frame do aluno): "bt full" gera "var = valor";
        # só interessam as do código do aluno (daí o gate 'frame_do_aluno'). Exclui prefixos "=="
        # (metadados Valgrind/ASan), " " (continuações multilinha do GDB) e "__" (internas do compilador).
        elif (
            frame_do_aluno
            and "=" in linha_strip
            and not linha_strip.startswith("==")
            and not linha_strip.startswith(" ")
            and not linha_strip.startswith("__")
        ):
            log_limpo.append(linha_strip)

    return '\n'.join(log_limpo)
