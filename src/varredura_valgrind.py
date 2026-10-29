"""
Varredura completa — Valgrind SEM congelar no 1º erro (complemento opcional da cascata).
========================================================================================
A cascata (Malhas 1, 2 e UBSan) para no PRIMEIRO erro: é dele que vêm a linha exata e a "foto"
das variáveis pelo GDB. Mas o primeiro erro pode esconder outros. MEDIDO no CodeBench: no
"Palíndromo" (WA02), a Malha 1 parou num estouro de 1 byte e não mostrou o `cont` sem valor, que
era o que gerava a saída errada.

Esta varredura roda o programa UMA vez a mais sob o Memcheck, sem `--vgdb-error`, deixando-o ir
até o fim, e devolve TODOS os erros distintos. Por que o Valgrind (e não o ASan) serve para isso,
segundo o manual oficial (valgrind.org/docs/manual, Memcheck e "core"):
  - por padrão ele anota o erro e deixa o programa continuar (o ASan aborta);
  - depois de reportar um valor não inicializado, passa a tratá-lo como definido, e o valor lido de
    um endereço inválido também é tratado como definido — um mesmo lixo não vira dezenas de avisos;
  - erros repetidos (mesmo tipo e mesma pilha) são impressos uma vez só.
Limite: o Memcheck NÃO impede o acesso inválido ("can't stop the access from happening"). Depois de
uma ESCRITA inválida a memória pode estar corrompida, e os erros seguintes podem ser consequência
dela. Por isso cada erro posterior a uma escrita inválida é marcado (`apos_escrita_invalida`).

Quando o erro principal veio da própria Malha 2, ela já deixa o programa seguir depois da "foto"
(continuar_apos_erro) e o relatório completo dela é reaproveitado por extrair_blocos — sem rodar
o Valgrind uma 2ª vez. A execução extra fica para quando o erro principal veio do ASan ou do UBSan.

Dividida em duas partes porque, na API, a execução roda no contêiner e a classificação no host:
  - coletar_blocos(...)    -> executa e devolve os blocos de texto do Memcheck (um por erro);
  - extrair_blocos(texto)  -> o mesmo, a partir de um relatório já pronto (o da Malha 2);
  - classificar_blocos(...) -> aplica a MESMA classificação da produção (classificar_erro) a cada
                              bloco, remove repetições e o erro principal já reportado.
"""

import os
import re
import resource
import subprocess

VARREDURA_TIMEOUT_S = 60

# Cabeçalho de cada erro do Memcheck no texto (1ª linha do bloco). Blocos sem isso (preâmbulo,
# HEAP/LEAK/ERROR SUMMARY) não são erros.
_RX_CABECALHO_ERRO = re.compile(
    r"^(?:Invalid (?:read|write|free)|Mismatched free|Conditional jump or move depends|"
    r"Use of uninitialised value|Syscall param|Source and destination overlap|"
    r"Argument '.*' of function|Jump to the invalid address|Process terminating with default action|"
    r".*bytes in .* blocks are (?:definitely|indirectly|possibly) lost)")
_RX_PREFIXO = re.compile(r"^==\d+== ?")


def coletar_blocos(caminho_codigo, binario_saida, entrada=None, flags_extra=None, limite_memoria_mb=None):
    """
    Compila (mesmas flags da Malha 2) e roda o programa sob o Memcheck até o fim.
    Devolve a lista de blocos de texto, um por erro, na ordem em que aconteceram. Lista vazia se
    não compilou, passou do tempo ou não houve erro.
    """
    compilacao = subprocess.run(
        ["gcc", "-std=gnu11", "-g", caminho_codigo, *(flags_extra or []), "-o", binario_saida],
        capture_output=True, text=True, errors="replace")
    if compilacao.returncode != 0:
        return []

    arquivo_log = binario_saida + ".memcheck.txt"

    def _limitar():
        if limite_memoria_mb:
            limite = limite_memoria_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limite, limite))

    try:
        # stdout descartado: a saída do programa não interessa e um laço que imprime sem parar não
        # enche a memória (problema visto no GDB da Malha 1 com saídas > 10 MB).
        subprocess.run(
            ["valgrind", "--leak-check=full", "--track-origins=yes", "--keep-stacktraces=alloc-and-free",
             "--read-var-info=yes", f"--log-file={arquivo_log}", binario_saida],
            input=entrada or "", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
            errors="replace", timeout=VARREDURA_TIMEOUT_S, preexec_fn=_limitar)
    except subprocess.TimeoutExpired:
        return []
    if not os.path.isfile(arquivo_log):
        return []
    with open(arquivo_log, encoding="utf-8", errors="replace") as f:
        return extrair_blocos(f.read())


def extrair_blocos(texto_memcheck):
    """
    Separa o relatório do Memcheck em blocos de texto, um por erro, na ordem em que aconteceram.
    Serve ao log da varredura e ao 'log_completo' da Malha 2 (que já deixou o programa ir até o
    fim, então não precisa rodar o Valgrind de novo).
    Só entram linhas com o prefixo "==PID==": no stderr da Malha 2 também chega o que o PROGRAMA
    escreve em stderr, que não é relatório. O prefixo é mantido: é o formato que o cwe.py reconhece.
    """
    # Blocos = linhas consecutivas não vazias (o Memcheck separa cada erro por uma linha "==PID== ").
    blocos, atual = [], []
    for linha in texto_memcheck.splitlines():
        if not _RX_PREFIXO.match(linha):
            continue
        if _RX_PREFIXO.sub("", linha).strip():
            atual.append(linha)
        elif atual:
            blocos.append(atual)
            atual = []
    if atual:
        blocos.append(atual)
    return ["\n".join(b) for b in blocos if _RX_CABECALHO_ERRO.match(_RX_PREFIXO.sub("", b[0]).strip())]


def classificar_blocos(blocos, codigo_fonte, nome_arquivo, principal=None):
    """
    Classifica cada bloco com a mesma função da produção e devolve a lista de erros distintos:
        [{"cwe_id", "cwe_nome", "linha_sintoma", "linha_causa", "apos_escrita_invalida"}, ...]
    `principal`: (cwe_id, linha_sintoma) do erro que a cascata já reportou. Erros na MESMA linha
    dele não são repetidos, mesmo com outro CWE: é o mesmo evento visto por outra ferramenta. MEDIDO:
    no RE05 o ASan diz 122 (estouro no heap) e o Memcheck, na mesma linha, 787 (escrita fora).
    Repetições (mesmo CWE na mesma linha) entram uma vez só, na 1ª ocorrência.
    """
    # Import adiado: no contêiner da API só coletar_blocos roda, e o llm_client exige `requests`.
    from src.llm_client import classificar_erro
    linha_principal = principal[1] if principal and principal[1] != "-" else None
    vistos = set()
    erros, houve_escrita_invalida = [], False
    for bloco in blocos:
        a = classificar_erro(bloco, codigo_fonte, nome_arquivo, log_bruto=bloco)
        chave = (a["cwe_id"], a["linha_sintoma"])
        if (a["cwe_id"] and a["cwe_id"] != "-" and chave not in vistos
                and a["linha_sintoma"] != linha_principal):
            vistos.add(chave)
            erros.append({"cwe_id": a["cwe_id"], "cwe_nome": a["cwe_nome"],
                          "linha_sintoma": a["linha_sintoma"], "linha_causa": a["linha_causa"],
                          "apos_escrita_invalida": houve_escrita_invalida})
        if "Invalid write" in bloco.splitlines()[0]:
            houve_escrita_invalida = True
    return erros


def resumir(erros):
    """Texto de uma célula de CSV: "CWE-457 L16; CWE-401 L12 (após escrita inválida)"."""
    if not erros:
        return "-"
    return "; ".join(f"{e['cwe_id']} L{e['linha_sintoma']}"
                     + (" (após escrita inválida)" if e["apos_escrita_invalida"] else "") for e in erros)
