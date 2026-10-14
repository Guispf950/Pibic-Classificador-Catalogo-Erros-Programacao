"""
app.py — Serviço FastAPI do pipeline (esqueleto testável).

Superfície REST (recursos no plural, com versão no caminho):
  • POST /v1/diagnostics       -> diagnóstico determinístico do erro (JSON). Aceita o código em
                                  JSON (application/json) OU como arquivo (multipart/form-data).
  • POST /v1/feedbacks         -> gera o feedback ao aluno em STREAMING (SSE), PERSISTE o resultado
                                  e devolve 201 com o id no header Location. Mesmo par de formatos.
  • GET  /v1/feedbacks         -> lista os feedbacks persistidos (para avaliação posterior).
  • GET  /v1/feedbacks/{id}    -> recupera um feedback persistido (404 se não existir).
  • GET  /v1/health            -> checagem de saúde do serviço.
  • GET  /teste                -> página HTML de teste do streaming (uso em demonstrações).

Teste em modo mock (sem Ollama/gcc/Valgrind/Docker): instalar requirements.txt e subir com
`uvicorn app:app --reload`. Para o pipeline REAL, ver pipeline_adapter.py (USAR_PIPELINE_REAL).
"""

import json
import os
import sys

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from pydantic import BaseModel, ValidationError

# Shim de caminho: coloca api/ no sys.path para `import pipeline_adapter`/`feedback_store` funcionar
# tanto de dentro de api/ (uvicorn app:app) quanto da raiz (uvicorn api.app:app).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# O adaptador isola a API do pipeline (modo mock ou real). Persistência de feedbacks à parte.
import pipeline_adapter as pipe
import feedback_store as store

# Prefixo de versão: permite evoluir a API mantendo /v1 no ar durante uma transição.
API_V1 = "/v1"

app = FastAPI(title="Servico de Analise e Feedback - PIBIC", version="1.0.0")

# ── CORS ──
# Segurança do navegador: por padrão, uma página de origem A não pode chamar por JavaScript uma API
# de origem B. O front do CodeBench roda em outra origem, então a API precisa autorizá-la aqui.
# "*" libera qualquer origem (cômodo em dev); em produção, restringir à origem exata do CodeBench.
# (CORS só afeta chamadas via navegador; curl/servidor-a-servidor ignoram.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # DEV: libera todas. PROD: domínio do CodeBench.
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Modelo de entrada (validação + doc automática do JSON) ──
class SubmissaoReq(BaseModel):
    codigo: str                        # código-fonte C do aluno (obrigatório)
    entrada: str                       # caso de teste (stdin) — OBRIGATÓRIO para a análise
                                       # dinâmica; pode ser "" só se o programa não lê nada.
    nome_arquivo: str = "submissao.c"  # usado para ancorar as anotações às linhas


# ── SSE (Server-Sent Events): cada evento é "data: <json>\n\n" ──
def sse(obj: dict) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"

# Headers que desligam buffers/cache — para os tokens fluírem na hora.
_SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}


# ── Campos internos que não saem na resposta ao cliente ──
# `codigo_anotado` (código com // @@) é uso interno para montar o prompt; devolvê-lo entregaria a
# localização exata do erro, furando a proposta socrática.
_CHAVES_INTERNAS = {"codigo_anotado"}


def _sem_internos(analise: dict) -> dict:
    return {k: v for k, v in analise.items() if k not in _CHAVES_INTERNAS}


# ── Extração unificada do payload: aceita JSON ou multipart no MESMO endpoint ──
async def _ler_upload(arquivo) -> str:
    if arquivo is None:
        return ""
    dados = await arquivo.read()
    return dados.decode("utf-8", "replace")


async def _extrair_payload(request: Request):
    """
    Devolve (codigo, entrada, nome_arquivo) a partir do corpo da requisição, decidindo pelo
    Content-Type: application/json (corpo JSON validado por Pydantic) ou multipart/form-data
    (campos `codigo` e `entrada`). Ambos os campos são OBRIGATÓRIOS — a `entrada` é o caso de
    teste que exercita a análise dinâmica (pode ser vazia só se o programa não lê stdin).
    Content-Type não suportado -> 415.
    """
    ctype = request.headers.get("content-type", "")

    if ctype.startswith("application/json"):
        try:
            dados = await request.json()
            req = SubmissaoReq(**dados)   # entrada sem default -> ausência gera ValidationError
        except ValidationError as e:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.errors())
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="JSON inválido.")
        return req.codigo, req.entrada, req.nome_arquivo

    if ctype.startswith("multipart/form-data"):
        form = await request.form()
        arquivo_codigo = form.get("codigo")
        if arquivo_codigo is None or not hasattr(arquivo_codigo, "read"):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail="Campo de arquivo 'codigo' é obrigatório no multipart.")
        campo_entrada = form.get("entrada")
        if campo_entrada is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail="Campo 'entrada' é obrigatório (o caso de teste; pode ser vazio).")
        codigo = await _ler_upload(arquivo_codigo)
        # entrada pode vir como arquivo (UploadFile) ou campo de texto do form.
        entrada = await _ler_upload(campo_entrada) if hasattr(campo_entrada, "read") else str(campo_entrada)
        nome = os.path.basename(getattr(arquivo_codigo, "filename", "") or "submissao.c")
        return codigo, entrada, nome

    raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        detail="Use application/json ou multipart/form-data.")


def _checar_infra(analise: dict):
    """Falha de infraestrutura (sandbox/Docker/runner) -> 503, não um diagnóstico falso."""
    if analise.get("erro_infra"):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=analise.get("detalhe") or "Dependência de análise indisponível.")


# ══════════════════════════════════════════════════════════════════════════════
# RECURSO: diagnostics  (POST /v1/diagnostics)
# ══════════════════════════════════════════════════════════════════════════════
@app.post(f"{API_V1}/diagnostics")
async def criar_diagnostico(request: Request):
    """
    Cria o diagnóstico determinístico do código (sem LLM) e o devolve como JSON.
    Aceita o código em JSON ({codigo, entrada, nome_arquivo}) ou como arquivo (multipart).
    """
    codigo, entrada, nome_arquivo = await _extrair_payload(request)
    resultado = pipe.analisar(codigo, entrada, nome_arquivo)
    _checar_infra(resultado)
    return JSONResponse(_sem_internos(resultado), status_code=status.HTTP_200_OK)


# ══════════════════════════════════════════════════════════════════════════════
# RECURSO: feedbacks  (POST cria+persiste; GET lista; GET/{id} recupera)
# ══════════════════════════════════════════════════════════════════════════════
def _eventos_feedback(codigo, entrada, nome_arquivo, feedback_id):
    """
    Gerador dos eventos SSE do feedback. Emite: meta (id) -> status -> diagnostico -> token* -> fim.
    Acumula o texto e PERSISTE ao final (só quando há erro real com feedback). Falhas de infra são
    entregues como evento 'erro' (o status HTTP já foi 201 quando o stream começou).
    """
    yield sse({"tipo": "meta", "id": feedback_id})
    yield sse({"tipo": "status", "msg": "Analisando seu código..."})

    analise = pipe.analisar(codigo, entrada, nome_arquivo)
    analise["nome_arquivo"] = nome_arquivo

    if analise.get("erro_infra"):
        yield sse({"tipo": "erro", "msg": analise.get("detalhe") or "Dependência de análise indisponível."})
        return

    yield sse({"tipo": "diagnostico", "dados": _sem_internos(analise)})

    partes = []
    for token in pipe.stream_feedback(analise, codigo):
        partes.append(token)
        yield sse({"tipo": "token", "texto": token})

    # Persiste só quando houve erro real (feedback pedagógico); código limpo não tem o que avaliar.
    if not analise.get("sem_erro"):
        store.salvar_feedback(
            feedback_id, codigo, analise, "".join(partes),
            pipeline_real=getattr(pipe, "USAR_PIPELINE_REAL", False),
        )

    yield sse({"tipo": "fim", "id": feedback_id})


@app.post(f"{API_V1}/feedbacks")
async def criar_feedback(request: Request):
    """
    Gera o feedback ao aluno em STREAMING (SSE), persiste o resultado e devolve 201 Created com o id
    no header Location (GET /v1/feedbacks/{id} recupera depois). Eventos: meta, status, diagnostico,
    token*, fim. Aceita o código em JSON ou multipart.
    """
    codigo, entrada, nome_arquivo = await _extrair_payload(request)
    feedback_id = store._novo_id()   # gerado antes do stream para ir no header Location
    headers = {**_SSE_HEADERS, "Location": f"{API_V1}/feedbacks/{feedback_id}"}
    return StreamingResponse(
        _eventos_feedback(codigo, entrada, nome_arquivo, feedback_id),
        media_type="text/event-stream",
        headers=headers,
        status_code=status.HTTP_201_CREATED,
    )


@app.get(f"{API_V1}/feedbacks")
def listar_feedbacks():
    """Lista os feedbacks persistidos (resumo), do mais recente ao mais antigo."""
    return {"itens": store.listar_feedbacks()}


@app.get(f"{API_V1}/feedbacks/{{feedback_id}}")
def obter_feedback(feedback_id: str):
    """Recupera um feedback persistido pelo id, ou 404 se não existir."""
    registro = store.obter_feedback(feedback_id)
    if registro is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feedback não encontrado.")
    return registro


# ══════════════════════════════════════════════════════════════════════════════
# Rotas auxiliares
# ══════════════════════════════════════════════════════════════════════════════
@app.get(f"{API_V1}/health")
def health():
    """Checagem de saúde do serviço."""
    return {"ok": True, "pipeline_real": os.environ.get("USAR_PIPELINE_REAL", "0") == "1"}


@app.get("/teste")
def pagina_teste():
    """Serve a página HTML que consome o /v1/feedbacks via SSE (para demonstrações)."""
    return FileResponse(os.path.join(os.path.dirname(__file__), "teste_sse.html"))
