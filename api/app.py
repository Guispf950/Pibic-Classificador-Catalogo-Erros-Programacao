"""
app.py — Serviço FastAPI do pipeline (esqueleto testável).
==========================================================

Expõe DOIS endpoints, exatamente como combinado:
  • POST /analisar  -> resposta JSON (rápida): diagnóstico determinístico do erro.
  • POST /feedback  -> resposta em STREAMING (SSE): o feedback ao aluno "sendo digitado".

Como testar AGORA (modo mock, sem depender de Ollama/gcc/Valgrind/Docker):
  1) pip install -r requirements.txt
  2) uvicorn app:app --reload           (sobe o servidor em http://127.0.0.1:8000)
  3) /analisar  -> teste no Insomnia/Postman/curl (é um POST JSON comum).
  4) /feedback  -> teste com `curl -N` (ver README) ou abrindo http://127.0.0.1:8000/teste

Para ligar o pipeline REAL, veja pipeline_adapter.py (variável USAR_PIPELINE_REAL).
"""

import json
import os
import sys

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from pydantic import BaseModel

# Shim de caminho: garante que a pasta api/ (onde está pipeline_adapter.py) esteja no
# sys.path. Assim `import pipeline_adapter` funciona tanto rodando de dentro de api/
# (uvicorn app:app) quanto da RAIZ do projeto (uvicorn api.app:app).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# O "adaptador" isola a API do pipeline: aqui a API só chama funções de alto nível,
# e o adapter decide se responde com dados MOCK (padrão) ou chama o pipeline real.
import pipeline_adapter as pipe

# Cria a aplicação FastAPI. O objeto `app` é o que o uvicorn carrega ("app:app").
app = FastAPI(title="Servico de Analise e Feedback - PIBIC", version="0.1.0")

# ── CORS ──────────────────────────────────────────────────────────────────────
# CORS controla quais ORIGENS (domínios) do navegador podem chamar esta API por
# JavaScript. A página de teste (teste_sse.html) e, no futuro, o front do CodeBench
# rodam em outra origem; sem liberar o CORS, o navegador BLOQUEIA a chamada.
# Em produção, troque "*" pela origem exata do CodeBench.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # DEV: libera todo mundo. PROD: coloque o domínio do CodeBench.
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Modelos de entrada (validação automática pelo Pydantic) ───────────────────
# O FastAPI usa estes modelos para: (1) validar o JSON recebido, (2) gerar a doc
# automática em /docs. Se faltar um campo obrigatório, a API já responde 422.
class AnalisarReq(BaseModel):
    codigo: str                      # código-fonte C do aluno
    entrada: str = ""                # conteúdo do caso de teste (.in), se houver
    nome_arquivo: str = "submissao.c"  # usado para ancorar as anotações às linhas


class FeedbackReq(BaseModel):
    codigo: str
    entrada: str = ""
    nome_arquivo: str = "submissao.c"


# ── Utilitário: formata um evento no padrão SSE ───────────────────────────────
# SSE (Server-Sent Events) transmite eventos de texto. O FORMATO na rede é simples:
# cada evento é uma linha "data: <conteúdo>" seguida de UMA LINHA EM BRANCO.
# Aqui mandamos um JSON por evento, para o cliente saber o "tipo" de cada pedaço.
def sse(obj: dict) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


# ── Campos INTERNOS que não devem sair na resposta ao cliente ─────────────────
# `codigo_anotado` (código com // @@ [SINTOMA]/[CAUSA]) é uso INTERNO: serve para
# montar o prompt do feedback. Devolvê-lo ao cliente entregaria a localização exata
# do erro — o que fura a proposta socrática. Fica no dict internamente, mas é
# removido do que vai pela rede.
_CHAVES_INTERNAS = {"codigo_anotado"}


def _sem_internos(analise: dict) -> dict:
    """Devolve uma cópia da análise SEM os campos de uso interno (não vazam ao cliente)."""
    return {k: v for k, v in analise.items() if k not in _CHAVES_INTERNAS}


# ── Gerador de eventos do feedback (usado pelo /feedback e pelo /feedback_arquivo) ──
# Fonte ÚNICA da lógica de streaming, para os dois endpoints não divergirem.
def _eventos_feedback(codigo: str, entrada: str, nome_arquivo: str):
    # 1) progresso imediato: evita a "tela parada" enquanto a análise roda.
    yield sse({"tipo": "status", "msg": "Analisando seu código..."})
    # 2) parte pesada e determinística (ASan/Valgrind) roda ANTES do LLM.
    analise = pipe.analisar(codigo, entrada, nome_arquivo)
    # Ao cliente vai a versão SEM campos internos (sem codigo_anotado)...
    yield sse({"tipo": "diagnostico", "dados": _sem_internos(analise)})
    # 3) ...mas o passo de feedback usa a análise COMPLETA (precisa do codigo_anotado).
    for token in pipe.stream_feedback(analise, codigo):
        yield sse({"tipo": "token", "texto": token})
    # 4) fim do stream.
    yield sse({"tipo": "fim"})


# Headers que desligam buffers/cache — para os tokens fluírem na hora (SSE).
_SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}


# ── Endpoint 1: /analisar (JSON síncrono) ─────────────────────────────────────
@app.post("/analisar")
def analisar(req: AnalisarReq):
    """
    Recebe o código + a entrada, roda a análise (determinística) e devolve o
    diagnóstico como JSON. É rápido de testar no Insomnia (POST com corpo JSON).
    """
    resultado = pipe.analisar(req.codigo, req.entrada, req.nome_arquivo)
    return JSONResponse(_sem_internos(resultado))


# ── Endpoint 2: /feedback (streaming SSE) ─────────────────────────────────────
@app.post("/feedback")
def feedback(req: FeedbackReq):
    """
    Gera o feedback ao aluno em STREAMING. A ideia: o aluno não espera olhando uma
    tela parada — ele recebe eventos conforme o servidor avança:
      1) 'status'       -> "analisando seu código..." (feedback imediato de progresso)
      2) 'diagnostico'  -> o resultado determinístico (tipo do erro, linha) já pronto
      3) 'token'*       -> os pedaços do texto do LLM, um a um (efeito "digitando")
      4) 'fim'          -> sinaliza o término
    """

    # StreamingResponse + media_type text/event-stream = resposta SSE. O gerador
    # compartilhado (_eventos_feedback) é o coração do streaming: cada yield envia um
    # pedaço na hora, sem esperar o resto ficar pronto.
    return StreamingResponse(
        _eventos_feedback(req.codigo, req.entrada, req.nome_arquivo),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints de TESTE por UPLOAD DE ARQUIVO (multipart) — sem escapar \n na mão.
# ══════════════════════════════════════════════════════════════════════════════
# Feitos para testar no Insomnia/Postman/curl anexando os arquivos direto:
#   • codigo  -> o .c do aluno (obrigatório)
#   • entrada -> o .in do caso de teste (opcional; ausente = sem stdin)
# Assim você NÃO precisa colocar o código dentro de um JSON com \n. A integração
# real com o CodeBench continua usando /analisar e /feedback (JSON).

async def _ler_upload(arquivo) -> str:
    """Lê um UploadFile e devolve o conteúdo como texto (ou '' se não veio)."""
    if arquivo is None:
        return ""
    dados = await arquivo.read()
    return dados.decode("utf-8", "replace")


@app.post("/analisar_arquivo")
async def analisar_arquivo(codigo: UploadFile = File(...),
                           entrada: UploadFile | None = File(None)):
    """Igual a /analisar, mas recebe o .c (e opcionalmente o .in) como ARQUIVOS."""
    codigo_txt = await _ler_upload(codigo)
    entrada_txt = await _ler_upload(entrada)
    nome = os.path.basename(codigo.filename or "submissao.c")
    return JSONResponse(_sem_internos(pipe.analisar(codigo_txt, entrada_txt, nome)))


@app.post("/feedback_arquivo")
async def feedback_arquivo(codigo: UploadFile = File(...),
                           entrada: UploadFile | None = File(None)):
    """Igual a /feedback (streaming SSE), mas recebe o .c (e o .in) como ARQUIVOS."""
    codigo_txt = await _ler_upload(codigo)
    entrada_txt = await _ler_upload(entrada)
    nome = os.path.basename(codigo.filename or "submissao.c")
    return StreamingResponse(
        _eventos_feedback(codigo_txt, entrada_txt, nome),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )


# ── Rotas auxiliares (saúde e página de teste) ────────────────────────────────
@app.get("/saude")
def saude():
    """Endpoint simples para checar se a API está de pé."""
    return {"ok": True, "pipeline_real": os.environ.get("USAR_PIPELINE_REAL", "0") == "1"}


@app.get("/teste")
def pagina_teste():
    """Serve a página HTML que consome o /feedback via SSE (para testar no navegador)."""
    return FileResponse(os.path.join(os.path.dirname(__file__), "teste_sse.html"))
