"""
Configuração central do pipeline.
================================

Reúne, num único lugar, as constantes e variáveis de configuração — caminhos, chaves do
LLM, o modo de anotação (variável dos experimentos) e os interruptores das malhas.
Editar o comportamento do pipeline é editar AQUI, sem caçar constantes espalhadas.

Todos os módulos importam daqui:  from src.config import <NOME>
"""

import os


# ── Caminhos ────────────────────────────────────────────────────────────────
# Pasta com as submissões a analisar (dados). Aponte para o subconjunto desejado.
PASTA_CODIGOS = "./data/submissoes_CE_codebench"
# Catálogo de saída (CSV) e pasta dos códigos anotados (// @@).
ARQUIVO_CSV_SAIDA = "./output/catalogo_erros_codebench.csv"
PASTA_ANOTADOS = "./output/codigos_anotados"
# Pasta dos feedbacks formativos (um .txt por submissão com erro).
PASTA_FEEDBACKS = "./output/feedbacks"
# Base de conhecimento (KB): um documento por CWE, recuperado por chave exata.
PASTA_KB = "./base_conhecimento"


# ── Malha 3 (perfilamento de complexidade) ──────────────────────────────────
# Exploratória; em exercícios de entrada fixa (ex.: AVL por sentinela) ela trava.
# False = desativada. Para reativar, basta trocar para True.
MALHA_3_ATIVA = False


# ── LLM local (Ollama) ──────────────────────────────────────────────────────
URL_LLM_LOCAL = "http://192.168.0.105:11434/api/generate"
NOME_MODELO = "qwen2.5-coder:7b"

# Duas temperaturas, uma por FASE (cada chamada ao LLM usa a sua):
#   Classificação (1ª chamada): 0.0 = DETERMINÍSTICA. Queremos o rótulo mais estável
#       possível; evita alucinação ao classificar o erro e é padrão no artigo "Exploring the Responses of Large Language Models to Beginner
#       Programmers’ Help Requests" e o FLAME (outro artigo) usa 0.1 

#   Feedback (2ª chamada): um pouco mais alta -> texto mais natural e didático ao aluno,
#       sem virar imprevisível, nesse caso 0.7 
TEMPERATURA_CLASSIFICACAO = 0.0
TEMPERATURA_FEEDBACK = 0.7


# ── Modo de anotação — variável dos experimentos de ablação (estilo FLAME) ──
#   "inline"   -> código anotado com // @@ nas linhas do erro   (padrão)
#   "numerica" -> código original + as linhas do erro em texto  (o "FLAME_num")
#   "nenhuma"  -> código original, sem dica de linha            (baseline)
# Trocável SEM editar código, via variável de ambiente:
#   ANOTACAO_MODO=numerica python orquestrador.py
MODO_ANOTACAO = os.environ.get("ANOTACAO_MODO", "inline").strip().lower()
if MODO_ANOTACAO not in ("inline", "numerica", "nenhuma"):
    MODO_ANOTACAO = "inline"   # valor desconhecido -> cai no padrão, sem quebrar


# ── Sincronização do Valgrind (Malha 2) ─────────────────────────────────────
VALGRIND_TIMEOUT_S = 120.0   # teto de segurança (protege contra loop infinito)
VALGRIND_POLL_S = 0.1        # intervalo entre verificações de estado (poll)
