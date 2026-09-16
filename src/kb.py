"""
Recuperação da Base de Conhecimento (KB) por CHAVE EXATA (o ID do CWE).

Dado o CWE já determinado deterministicamente (src/cwe.py), recupera o documento curado
correspondente em `base_conhecimento/<CWE-ID>.md`.

Por que chave exata (e não busca semântica / embeddings): o CWE é uma chave estruturada e
confiável vinda da ferramenta, não uma consulta em linguagem natural. Recuperar por chave é
o caso extremo de "metadata filtering" — restringe a recuperação a UM documento. Vantagens,
ancoradas na literatura:
  1. Elimina o "distrator" por construção. Passagens irrelevantes-porém-parecidas enganam o
     LLM e pioram a geração ("The Distracting Effect", 2025), dano amplificado sob capacidade
     limitada (modelo 7B). Sem ranking semântico não há chunk errado para distrair.
  2. Determinístico e auditável — combina com a espinha do pipeline.
  3. Zero infraestrutura — sem vector DB nem modelo de embeddings; a "busca" é uma leitura.
  4. Latência de leitura de um arquivo.

Degradação graciosa: sem documento para o CWE, retorna "" e o pipeline segue sem a KB.
"""

import os
import re

from src.config import PASTA_KB


# O CWE vem sempre do mapeamento interno (formato "CWE-<números>"), mas o formato é validado
# antes de montar o caminho — evita usar valor inesperado como nome de arquivo (path traversal).
_FORMATO_CWE = re.compile(r"^CWE-\d+$")


def recuperar_kb(cwe_id):
    """
    Recupera o documento curado do CWE por chave exata.
    cwe_id: identificador (ex.: "CWE-416"). "-", vazio ou inválido -> "".
    Retorna o conteúdo de `base_conhecimento/<CWE-ID>.md`, ou "" se não houver documento.
    """
    if not cwe_id:
        return ""
    chave = str(cwe_id).strip().upper()
    if not _FORMATO_CWE.match(chave):   # "-" (sem CWE) ou lixo -> nada a recuperar
        return ""

    caminho = os.path.join(PASTA_KB, f"{chave}.md")
    if not os.path.isfile(caminho):     # CWE ainda sem documento curado -> segue sem KB
        return ""

    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""
