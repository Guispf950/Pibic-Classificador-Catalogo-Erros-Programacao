"""
Configuração central do pipeline: caminhos, parâmetros do LLM, modo de anotação e
interruptores das malhas. Todos os módulos importam daqui (from src.config import ...).
"""

import os


# ── Caminhos ──
PASTA_CODIGOS = "./data/submissoes_CE_codebench"          # submissões a analisar
ARQUIVO_CSV_SAIDA = "./output/catalogo_erros_codebench.csv"
PASTA_ANOTADOS = "./output/codigos_anotados"              # códigos com anotação // @@
PASTA_FEEDBACKS = "./output/feedbacks"                    # um .txt por submissão com erro
PASTA_KB = "./base_conhecimento"                          # um documento por CWE


# ── Malha 3 (perfilamento de complexidade) ──
# Exploratória; trava em exercícios de entrada fixa. False = desativada.
MALHA_3_ATIVA = False


# ── LLM local (Ollama) ──
URL_LLM_LOCAL = "http://192.168.0.105:11434/api/generate"
NOME_MODELO = "qwen2.5-coder:7b"

# Timeout generoso: a 1ª chamada carrega o modelo na memória (cold start).
LLM_TIMEOUT_S = int(os.environ.get("LLM_TIMEOUT_S", "300"))
# Mantém o modelo na memória do Ollama entre chamadas (evita novo cold start).
LLM_KEEP_ALIVE = os.environ.get("LLM_KEEP_ALIVE", "30m")

# Uma temperatura por fase: classificação determinística; feedback mais natural.
TEMPERATURA_CLASSIFICACAO = 0.0
TEMPERATURA_FEEDBACK = 0.7


# ── Modo de anotação (variável dos experimentos de ablação, estilo FLAME) ──
#   "inline"   -> código anotado com // @@ nas linhas do erro (padrão)
#   "numerica" -> código original + as linhas do erro em texto
#   "nenhuma"  -> código original, sem dica de linha (baseline)
# Selecionável por variável de ambiente: ANOTACAO_MODO=numerica python orquestrador.py
MODO_ANOTACAO = os.environ.get("ANOTACAO_MODO", "inline").strip().lower()
if MODO_ANOTACAO not in ("inline", "numerica", "nenhuma"):
    MODO_ANOTACAO = "inline"   # valor inválido cai no padrão


# ── Sincronização do Valgrind (Malha 2) ──
VALGRIND_TIMEOUT_S = 120.0   # teto de segurança contra loop infinito
VALGRIND_POLL_S = 0.1        # intervalo entre verificações de estado
