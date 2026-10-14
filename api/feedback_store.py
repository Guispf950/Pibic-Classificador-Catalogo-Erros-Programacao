"""
feedback_store.py — persistência dos feedbacks gerados pela API.

Cada feedback gerado é salvo como um JSON estruturado em PASTA_FEEDBACKS_API, com o diagnóstico
determinístico e o texto completo. O objetivo é a avaliação posterior da qualidade pedagógica dos
feedbacks — por isso guarda-se o contexto (código, CWE, linhas, modelo, modo de anotação), não só
o texto. É um armazenamento simples em arquivos (um JSON por feedback), sem banco de dados.
"""

import os
import re
import sys
import json
import uuid
from datetime import datetime, timezone

# Shim de caminho: garante a RAIZ do projeto no sys.path para `from src...` resolver,
# independentemente da ordem de import (a raiz é a pasta-mãe de api/).
_RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _RAIZ not in sys.path:
    sys.path.insert(0, _RAIZ)

from src.config import PASTA_FEEDBACKS_API, NOME_MODELO, MODO_ANOTACAO


# Aceita apenas ids no formato que este módulo gera (data + hex), como defesa contra path traversal
# em GET /v1/feedbacks/{id}.
_FORMATO_ID = re.compile(r"^\d{8}T\d{6}_[0-9a-f]{8}$")


def _novo_id():
    """Gera um id ordenável por tempo: AAAAMMDDThhmmss_<8 hex>."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{ts}_{uuid.uuid4().hex[:8]}"


def _caminho(feedback_id):
    return os.path.join(PASTA_FEEDBACKS_API, f"{feedback_id}.json")


def salvar_feedback(feedback_id, codigo, analise, feedback_texto, pipeline_real):
    """
    Grava um feedback e seu contexto como <id>.json. Recebe o id já gerado (o endpoint precisa
    dele antes de iniciar o streaming, para devolvê-lo no header Location). Falha de escrita não
    interrompe a resposta ao aluno (persistência é best-effort).
    """
    registro = {
        "id": feedback_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "nome_arquivo": analise.get("nome_arquivo") or "submissao.c",
        "modelo": NOME_MODELO,
        "modo_anotacao": MODO_ANOTACAO,
        "pipeline_real": pipeline_real,
        "diagnostico": {
            "tipo_erro": analise.get("tipo_erro", "-"),
            "cwe_id": analise.get("cwe_id", "-"),
            "cwe_nome": analise.get("cwe_nome", "-"),
            "linha_sintoma": analise.get("linha_sintoma", "-"),
            "linha_causa": analise.get("linha_causa", "-"),
            "evidencia_log": analise.get("evidencia_log", "-"),
            "ferramenta": analise.get("ferramenta", "-"),
        },
        "codigo": codigo,
        "feedback": feedback_texto,
    }
    try:
        os.makedirs(PASTA_FEEDBACKS_API, exist_ok=True)
        with open(_caminho(feedback_id), "w", encoding="utf-8") as f:
            json.dump(registro, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[Aviso] Falha ao persistir feedback {feedback_id}: {e}")
    return registro


def listar_feedbacks():
    """
    Lista os feedbacks salvos (resumo, sem o texto/código completos), ordenados do mais recente
    para o mais antigo. Serve à navegação da coleção (GET /v1/feedbacks).
    """
    if not os.path.isdir(PASTA_FEEDBACKS_API):
        return []
    resumos = []
    for nome in os.listdir(PASTA_FEEDBACKS_API):
        if not nome.endswith(".json"):
            continue
        try:
            with open(os.path.join(PASTA_FEEDBACKS_API, nome), "r", encoding="utf-8") as f:
                reg = json.load(f)
            diag = reg.get("diagnostico", {})
            resumos.append({
                "id": reg.get("id"),
                "timestamp_utc": reg.get("timestamp_utc"),
                "nome_arquivo": reg.get("nome_arquivo"),
                "tipo_erro": diag.get("tipo_erro"),
                "cwe_id": diag.get("cwe_id"),
                "pipeline_real": reg.get("pipeline_real"),
            })
        except Exception:
            continue  # arquivo corrompido/parcial: ignora
    resumos.sort(key=lambda r: r.get("timestamp_utc") or "", reverse=True)
    return resumos


def obter_feedback(feedback_id):
    """Retorna o registro completo de um feedback, ou None se o id for inválido/inexistente."""
    if not feedback_id or not _FORMATO_ID.match(feedback_id):
        return None
    caminho = _caminho(feedback_id)
    if not os.path.isfile(caminho):
        return None
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None
