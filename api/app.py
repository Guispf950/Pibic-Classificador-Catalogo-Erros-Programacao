"""
app.py — Serviço FastAPI do pipeline (esqueleto testável).

Expõe dois endpoints:
  • POST /analisar  -> resposta JSON (rápida): diagnóstico determinístico do erro.
  • POST /feedback  -> resposta em STREAMING (SSE): o feedback ao aluno "sendo digitado".

Teste em modo mock (sem Ollama/gcc/Valgrind/Docker): instalar requirements.txt, subir com
`uvicorn app:app --reload`, chamar /analisar (POST JSON) e /feedback (`curl -N` ou /teste no
navegador). Para o pipeline REAL, ver pipeline_adapter.py (variável USAR_PIPELINE_REAL).
"""

import json
import os
import sys

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from pydantic import BaseModel

# Shim de caminho: coloca api/ (onde está pipeline_adapter.py) no sys.path, para
# `import pipeline_adapter` funcionar tanto de dentro de api/ (uvicorn app:app) quanto da raiz
# (uvicorn api.app:app).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# O adaptador isola a API do pipeline: a API só chama funções de alto nível, e o adapter decide
# entre dados MOCK (padrão) ou o pipeline real.
import pipeline_adapter as pipe

# Aplicação FastAPI (o objeto `app` é o que o uvicorn carrega em "app:app").
app = FastAPI(title="Servico de Analise e Feedback - PIBIC", version="0.1.0")

# ── CORS ──
# Controla quais origens (domínios) do navegador podem chamar esta API por JavaScript. A página de
# teste e, no futuro, o front do CodeBench rodam em outra origem; sem CORS o navegador bloqueia a
# chamada. Em produção, "*" deve virar a origem exata do CodeBench.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # DEV: libera todas. PROD: domínio do CodeBench.
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Modelos de entrada (validação automática pelo Pydantic) ──
# O FastAPI usa estes modelos para validar o JSON recebido e gerar a doc em /docs. Campo
# obrigatório ausente -> resposta 422.
class AnalisarReq(BaseModel):
    codigo: str                      # código-fonte C do aluno
    entrada: str = ""                # conteúdo do caso de teste (.in), se houver
    nome_arquivo: str = "submissao.c"  # usado para ancorar as anotações às linhas


class FeedbackReq(BaseModel):
    codigo: str
    entrada: str = ""
    nome_arquivo: str = "submissao.c"


# ── Utilitário: formata um evento no padrão SSE ──
# SSE (Server-Sent Events) transmite eventos de texto: cada evento é uma linha "data: <conteúdo>"
# seguida de uma linha em branco. Aqui vai um JSON por evento, para o cliente saber o tipo de cada.
def sse(obj: dict) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


# ── Campos INTERNOS que não saem na resposta ao cliente ──
# `codigo_anotado` (código com // @@ [SINTOMA]/[CAUSA]) é de uso interno para montar o prompt do
# feedback. Devolvê-lo entregaria a localização exata do erro, furando a proposta socrática. Fica
# no dict internamente, mas é removido do que trafega pela rede.
_CHAVES_INTERNAS = {"codigo_anotado"}


def _sem_internos(analise: dict) -> dict:
    """Cópia da análise sem os campos de uso interno (não vazam ao cliente)."""
    return {k: v for k, v in analise.items() if k not in _CHAVES_INTERNAS}


# ── Gerador de eventos do feedback (usado por /feedback e /feedback_arquivo) ──
# Fonte única da lógica de streaming, para os dois endpoints não divergirem.
def _eventos_feedback(codigo: str, entrada: str, nome_arquivo: str):
    # 1) progresso imediato: evita a tela parada enquanto a análise roda.
    yield sse({"tipo": "status", "msg": "Analisando seu código..."})
    # 2) parte pesada e determinística (ASan/Valgrind) roda ANTES do LLM.
    analise = pipe.analisar(codigo, entrada, nome_arquivo)
    # Ao cliente vai a versão sem campos internos (sem codigo_anotado)...
    yield sse({"tipo": "diagnostico", "dados": _sem_internos(analise)})
    # 3) ...mas o feedback usa a análise completa (precisa do codigo_anotado).
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
    Recebe código + entrada, roda a análise determinística e devolve o diagnóstico como JSON.
    """
    resultado = pipe.analisar(req.codigo, req.entrada, req.nome_arquivo)
    return JSONResponse(_sem_internos(resultado))


# ── Endpoint 2: /feedback (streaming SSE) ─────────────────────────────────────
@app.post("/feedback")
def feedback(req: FeedbackReq):
    """
    Gera o feedback ao aluno em STREAMING: o aluno recebe eventos conforme o servidor avança:
      1) 'status'       -> progresso imediato ("analisando...")
      2) 'diagnostico'  -> resultado determinístico (tipo do erro, linha) já pronto
      3) 'token'*       -> pedaços do texto do LLM, um a um (efeito "digitando")
      4) 'fim'          -> término
    """

    # StreamingResponse + media_type text/event-stream = resposta SSE. O gerador compartilhado
    # (_eventos_feedback) envia cada pedaço na hora, sem esperar o resto ficar pronto.
    return StreamingResponse(
        _eventos_feedback(req.codigo, req.entrada, req.nome_arquivo),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints de TESTE por UPLOAD DE ARQUIVO (multipart) — sem escapar \n na mão.
# ══════════════════════════════════════════════════════════════════════════════
# Para testar anexando os arquivos direto (Insomnia/Postman/curl):
#   • codigo  -> o .c do aluno (obrigatório)
#   • entrada -> o .in do caso de teste (opcional; ausente = sem stdin)
# Dispensa colocar o código dentro de um JSON com \n. A integração real com o CodeBench continua
# usando /analisar e /feedback (JSON).

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
