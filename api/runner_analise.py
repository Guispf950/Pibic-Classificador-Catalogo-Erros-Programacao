"""
runner_analise.py — roda DENTRO do contêiner Docker (é o "programa" da imagem).

A DETECÇÃO executa CÓDIGO NÃO CONFIÁVEL (o do aluno), então roda isolada no contêiner,
reaproveitando o mesmo pipeline (Malha 1 ASan+GDB e Malha 2 Valgrind) para paridade com o
orquestrador. O LLM (classificação e feedback) fica fora do contêiner, na API do host, porque o
contêiner roda com --network none (sem acesso ao Ollama).

O que o script faz: recebe o caminho do .c do aluno (montado em /work, só-leitura), roda a cascata
de detecção (Malha 1 -> Malha 2), limpa o log se achou erro (limpar_log_gdb) e imprime um JSON
após um marcador, para o sandbox.py ler.

Saída (stdout): os prints das malhas (ruído) e, ao final, a linha ===RESULTADO_JSON=== seguida de
uma linha JSON. O sandbox.py pega só o JSON.
"""

import sys
import os
import json

# /app é onde o Dockerfile copia o pacote `src/`; garante que esteja no path para os imports
# `from src...` funcionarem dentro do contêiner.
sys.path.insert(0, "/app")

from src.malha1_asan import executar_malha_1_asan          # ASan + GDB (erros espaciais)
from src.malha2_valgrind import executar_malha_2_valgrind  # Valgrind (não-inic., leaks)
from src.parser_logs import limpar_log_gdb                 # filtra o log antes do LLM

# Marcador que separa o RUÍDO (prints das malhas) do JSON de resultado. O sandbox.py
# procura por esta linha e lê o JSON logo depois — assim os prints não atrapalham.
MARCADOR = "===RESULTADO_JSON==="


def analisar_arquivo(caminho_codigo: str, entrada=None) -> dict:
    """
    Roda a cascata de detecção e devolve um dict serializável com o resultado.

    `entrada`: o stdin AUTORITATIVO (o caso de teste que a API recebeu do CodeBench).
    Quando fornecido, sobrepõe a heurística das malhas — a entrada usada é SEMPRE a que
    veio na requisição. `None` só no uso offline (fora da API).
    """
    nome_arquivo = os.path.basename(caminho_codigo)

    ferramenta = "Nenhuma"
    categoria = "memoria"       # distingue erro de MEMÓRIA de erro de COMPILAÇÃO
    resultado = None

    # ── MALHA 1: AddressSanitizer + GDB (fail-fast) ──────────────────────────
    resultado = executar_malha_1_asan(caminho_codigo, entrada=entrada)
    if resultado:
        tipo_m1 = resultado.get("tipo", "asan")
        if tipo_m1 == "compilacao":
            ferramenta = "Compilador (gcc)"
            categoria = "compilacao"
        elif tipo_m1 == "crash":
            ferramenta = f"ASan+GDB (crash: {resultado.get('sinal', 'sinal')})"
        else:
            ferramenta = "ASan+GDB"
    else:
        # ── MALHA 2: Valgrind + vgdb (só se a Malha 1 passou limpa) ───────────
        resultado = executar_malha_2_valgrind(caminho_codigo, entrada=entrada)
        if resultado:
            ferramenta = "Valgrind+vgdb"

    # ── Monta o resultado ────────────────────────────────────────────────────
    if resultado and resultado.get("log"):
        log_bruto = resultado["log"]
        log_limpo = limpar_log_gdb(log_bruto, nome_arquivo)
        return {
            "erro_encontrado": True,
            "ferramenta": ferramenta,
            "categoria": categoria,
            "log_bruto": log_bruto,
            "log_limpo": log_limpo,
        }

    # Nenhuma falha: código passou limpo nas malhas de memória.
    return {
        "erro_encontrado": False,
        "ferramenta": "Nenhuma (passou limpo)",
        "categoria": "nenhum",
        "log_bruto": "",
        "log_limpo": "",
    }


def _ler_entrada_montada():
    """
    Lê o caso de teste que o sandbox montou em /work/entrada.in.

    Se o arquivo existe (a API sempre o grava, mesmo vazio), seu conteúdo é a entrada AUTORITATIVA
    (retorna a string, que pode ser ""). Se não existe (uso fora da API), retorna None e as malhas
    caem na detecção offline.
    """
    caminho_in = "/work/entrada.in"
    if os.path.isfile(caminho_in):
        try:
            with open(caminho_in, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return None
    return None


if __name__ == "__main__":
    caminho = sys.argv[1] if len(sys.argv) > 1 else "/work/submissao.c"
    entrada = _ler_entrada_montada()
    try:
        saida = analisar_arquivo(caminho, entrada=entrada)
    except Exception as e:
        # Qualquer erro interno da detecção vira um resultado explícito (não derruba tudo).
        saida = {
            "erro_encontrado": False,
            "ferramenta": "Erro interno na detecção",
            "categoria": "erro_runner",
            "log_bruto": f"{type(e).__name__}: {e}",
            "log_limpo": "",
        }

    # Emite o marcador + o JSON numa única linha (o sandbox.py lê a partir daqui).
    print(MARCADOR, flush=True)
    print(json.dumps(saida, ensure_ascii=False), flush=True)
