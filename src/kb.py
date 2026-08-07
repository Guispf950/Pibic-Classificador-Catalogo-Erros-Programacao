"""
Recuperação da Base de Conhecimento (KB) por CHAVE EXATA (o ID do CWE).
======================================================================

Dado o CWE que o pipeline já determinou DETERMINISTICAMENTE (src/cwe.py), este módulo
recupera o documento curado correspondente em `base_conhecimento/<CWE-ID>.md`.

POR QUE CHAVE EXATA (e não busca semântica / embeddings):
    O CWE é uma chave estruturada e confiável, vinda da ferramenta — não uma consulta
    em linguagem natural. Recuperar por chave exata é o caso EXTREMO de "metadata
    filtering": em vez de rankear por similaridade, restringimos a recuperação a UM
    único documento. Isso importa por quatro motivos, todos ancorados na literatura:

      1. Elimina o "distrator" por construção. Passagens irrelevantes-porém-parecidas
         enganam o LLM e pioram a geração ("The Distracting Effect", 2025) — e esse dano
         é AMPLIFICADO sob capacidade limitada de modelo (o nosso 7B). Sem ranking
         semântico, não há chunk errado para distrair.
      2. Determinístico e auditável — combina com a espinha do pipeline (o mesmo motivo
         de o CWE não ser tarefa do LLM).
      3. Zero infraestrutura — não precisa de vector DB nem de um modelo de embeddings
         rodando ao lado do LLM local. A "busca" é uma leitura de arquivo.
      4. Latência ~ leitura de um arquivo.

    (Um SEGUNDO canal — por termos específicos da linguagem, ex.: funções citadas no
     código — pode ser somado depois. O canal primário por CWE resolve a explicação do
     TIPO do erro, que é o que a fase de feedback precisa.)

Degradação graciosa: se não houver documento para aquele CWE, retorna "" e o pipeline
segue sem a KB (nenhuma falha dura).
"""

import os
import re

from src.config import PASTA_KB


# O CWE sempre vem do nosso próprio mapeamento (formato "CWE-<números>"). Ainda assim,
# validamos o formato antes de montar o caminho — evita que qualquer valor inesperado
# seja usado como nome de arquivo (defesa contra path traversal).
_FORMATO_CWE = re.compile(r"^CWE-\d+$")


def recuperar_kb(cwe_id):
    """
    Recupera o documento curado do CWE por CHAVE EXATA.

    Parâmetro:
        cwe_id: o identificador (ex.: "CWE-416"). "-", vazio ou formato inválido -> "".

    Retorna:
        O conteúdo do arquivo `base_conhecimento/<CWE-ID>.md` como string, ou "" se
        não houver documento para esse CWE (ou o id for inválido).
    """
    if not cwe_id:
        return ""
    chave = str(cwe_id).strip().upper()
    if not _FORMATO_CWE.match(chave):   # ex.: "-" (sem CWE) ou lixo -> nada a recuperar
        return ""

    caminho = os.path.join(PASTA_KB, f"{chave}.md")
    if not os.path.isfile(caminho):     # CWE ainda sem documento curado -> segue sem KB
        return ""

    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""
