"""
experimentos.py — Núcleo comum dos experimentos (Juliet e CodeBench)
=====================================================================
Os dois avaliadores (avaliar_juliet.py e avaliar_codebench.py) usam este módulo para que as
rodadas sejam COMPARÁVEIS entre datasets:

  - mesmas colunas no início do CSV por item (COLUNAS_NUCLEO); as colunas próprias de cada
    dataset vêm depois;
  - mesmo começo no histórico (1 linha por rodada): data, versão do código, versão do dataset,
    seed, amostragem, % detectado, CWEs obtidos, tempo médio...;
  - mesmos parâmetros de linha de comando: --total N, --por-grupo N (grupo = CWE no Juliet,
    questão no CodeBench), --seed S e --todos-erros.

O que NÃO é comum, e por quê: o Juliet tem rótulo (o CWE esperado), então mede ACERTO (lentes
L1–L4); o CodeBench não tem rótulo, então mede DETECÇÃO e depende de revisão manual. A coluna
"Rótulo Esperado" fica "-" no CodeBench.
"""

import collections
import csv
import hashlib
import os
import subprocess
from datetime import datetime, timezone

# ── Colunas comuns do CSV por item (sempre nesta ordem, no início) ──
COLUNAS_NUCLEO = ["Dataset", "Item", "Grupo", "Rótulo Esperado", "Ferramenta", "Status Pipeline",
                  "CWE Obtido", "Nome CWE Obtido", "Linha Sintoma", "Linha Causa", "Outros Erros",
                  "Tempo (s)"]

# Status que contam como "o pipeline rodou" (fora: não compilou ou não foi analisado).
_FORA_DA_ANALISE = ("erro_compilacao", "nao_analisado")


def linha_nucleo(dataset, item, grupo, esperado, ferramenta, status, cwe, nome_cwe, sintoma, causa,
                 outros, tempo):
    """Dict com as colunas comuns, na ordem de COLUNAS_NUCLEO."""
    return dict(zip(COLUNAS_NUCLEO, (dataset, item, grupo, esperado, ferramenta, status, cwe, nome_cwe,
                                     sintoma, causa, outros, tempo)))


# ── Versões (para amarrar um resultado ao código e ao dataset que o produziram) ──

def _commit_lendo_pasta_git(raiz):
    """Commit curto lido direto de <raiz>/.git, sem o programa git (o contêiner de análise não o tem)."""
    pasta = os.path.join(raiz, ".git")
    try:
        with open(os.path.join(pasta, "HEAD"), encoding="utf-8") as f:
            head = f.read().strip()
        if not head.startswith("ref: "):
            return head[:7]                                   # HEAD destacado: já é o hash
        ref = head[5:]
        caminho_ref = os.path.join(pasta, *ref.split("/"))
        if os.path.isfile(caminho_ref):
            with open(caminho_ref, encoding="utf-8") as f:
                return f.read().strip()[:7]
        with open(os.path.join(pasta, "packed-refs"), encoding="utf-8") as f:
            for linha in f:
                if linha.rstrip().endswith(" " + ref):
                    return linha.split()[0][:7]
    except OSError:
        pass
    return None


def commit_codigo():
    """
    Commit curto do repositório; '+alterações' se src/ ou os avaliadores têm mudança não commitada.
    No contêiner (sem git) lê o commit da pasta .git, mas aí não dá para saber se há alteração:
    passe COMMIT_CODIGO no `docker run -e` para registrar o valor exato calculado no host.
    """
    if os.environ.get("COMMIT_CODIGO"):
        return os.environ["COMMIT_CODIGO"]
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            sujo = subprocess.run(["git", "status", "--porcelain", "src", "avaliar_juliet.py",
                                   "avaliar_codebench.py", "experimentos.py"],
                                  capture_output=True, text=True, timeout=5).stdout.strip()
            return r.stdout.strip() + ("+alterações" if sujo else "")
    except Exception:
        pass
    commit = _commit_lendo_pasta_git(".")
    return f"{commit} (alterações não verificadas)" if commit else "-"


def versao_dataset(raiz, arquivo_referencia=None):
    """Commit do dataset se ele for um repositório git; senão, SHA-256 (12 dígitos) do arquivo de referência."""
    try:
        r = subprocess.run(["git", "-C", raiz, "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    commit = _commit_lendo_pasta_git(raiz)
    if commit:
        return commit
    if arquivo_referencia and os.path.isfile(arquivo_referencia):
        h = hashlib.sha256()
        with open(arquivo_referencia, "rb") as f:
            for bloco in iter(lambda: f.read(1 << 20), b""):
                h.update(bloco)
        return "sha256:" + h.hexdigest()[:12]
    return "-"


# ── Arquivos acumulados e CSV incremental ──

def preparar_acumulado(caminho, campos):
    """
    True se `caminho` já existe com o MESMO cabeçalho (é só acrescentar). Se o cabeçalho mudou
    (o script ganhou colunas), o arquivo antigo é renomeado — preservado — e um novo começa.
    """
    if not os.path.isfile(caminho):
        return False
    with open(caminho, encoding="utf-8", newline="") as f:
        cabecalho = next(csv.reader(f), [])
    if cabecalho == campos:
        return True
    os.replace(caminho, caminho.replace(".csv", f"_ate_{datetime.now():%Y%m%d%H%M%S}.csv"))
    return False


class CsvIncremental:
    """CSV gravado linha a linha (cabeçalho na 1ª linha; flush a cada linha): uma queda no meio de
    uma rodada longa perde só o item em andamento."""

    def __init__(self, caminho):
        os.makedirs(os.path.dirname(caminho) or ".", exist_ok=True)
        self._arq = open(caminho, "w", newline="", encoding="utf-8")
        self._w = None

    def escrever(self, linha):
        if self._w is None:
            self._w = csv.DictWriter(self._arq, fieldnames=list(linha), extrasaction="ignore")
            self._w.writeheader()
        self._w.writerow(linha)
        self._arq.flush()

    def fechar(self):
        self._arq.close()


# ── Histórico comum ──

def resumo_nucleo(linhas):
    """Números comparáveis entre datasets, calculados só das colunas comuns."""
    analisados = [l for l in linhas if l["Status Pipeline"] not in _FORA_DA_ANALISE]
    detectados = [l for l in analisados if l["Status Pipeline"] == "detectado"]
    tempos = [float(l["Tempo (s)"]) for l in linhas if str(l["Tempo (s)"]).replace(".", "", 1).isdigit()]
    cwes = collections.Counter(l["CWE Obtido"] for l in detectados)
    return {
        "Itens": len(linhas),
        "Falhas de Compilação": sum(l["Status Pipeline"] == "erro_compilacao" for l in linhas),
        "Analisados": len(analisados),
        "Detectados": len(detectados),
        "Detecção (%)": round(100 * len(detectados) / len(analisados), 1) if analisados else 0,
        "Timeouts": sum(l["Status Pipeline"] == "timeout_malha" for l in analisados),
        "Erros Internos": sum(str(l["Status Pipeline"]).startswith("erro_interno") for l in analisados),
        "Itens com Outros Erros": sum(l["Outros Erros"] not in ("-", "") for l in linhas),
        "Tempo Médio (s)": round(sum(tempos) / len(tempos), 2) if tempos else 0,
        "CWEs Obtidos": "; ".join(f"{c}: {n}" for c, n in cwes.most_common()) or "-",
    }


def registrar_historico(caminho, dataset, versao_ds, seed, amostragem, filtro, todos_erros, linhas,
                        especificos=None):
    """Acrescenta 1 linha ao histórico: colunas comuns + `especificos` (as do dataset) no fim."""
    linha = {
        "Data/Hora (UTC)": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "Dataset": dataset,
        "Commit Código": commit_codigo(),
        "Versão Dataset": versao_ds,
        "Seed": seed,
        "Amostragem": amostragem,
        "Filtro": filtro,
        "Todos os Erros": "sim" if todos_erros else "não",
        **resumo_nucleo(linhas),
        **(especificos or {}),
    }
    os.makedirs(os.path.dirname(caminho) or ".", exist_ok=True)
    existe = preparar_acumulado(caminho, list(linha))
    with open(caminho, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(linha))
        if not existe:
            w.writeheader()
        w.writerow(linha)
    return linha


# ── Varredura completa (opcional, --todos-erros) ──

def outros_erros(caminho_fonte, binario_saida, entrada, flags_extra, principal, limite_memoria_mb=None,
                 log_completo=None):
    """
    Devolve o texto da coluna "Outros Erros" (todos os erros distintos além do principal já
    reportado pela cascata). `log_completo`: relatório do Memcheck que a Malha 2 já produziu ao
    deixar o programa ir até o fim; sem ele, roda a varredura do Valgrind. Ver src/varredura_valgrind.py.
    """
    from src.varredura_valgrind import coletar_blocos, extrair_blocos, classificar_blocos, resumir
    if log_completo is not None:
        blocos = extrair_blocos(log_completo)
    else:
        blocos = coletar_blocos(caminho_fonte, binario_saida, entrada=entrada, flags_extra=flags_extra,
                                limite_memoria_mb=limite_memoria_mb)
    with open(caminho_fonte, encoding="utf-8", errors="replace") as f:
        codigo = f.read()
    return resumir(classificar_blocos(blocos, codigo, os.path.basename(caminho_fonte), principal=principal))
