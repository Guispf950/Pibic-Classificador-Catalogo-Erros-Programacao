"""
Avaliação do pipeline em submissões REAIS do CodeBench (dataset cb-dataset, ver
data/codebench/README.md).

O dataset traz o código de cada aluno e os casos de teste do professor, mas NÃO traz o veredito.
Este script faz três coisas, nesta ordem:

  1. INVENTÁRIO — percorre o dataset inteiro e registra TODA submissão de lista em C, marcando
     "incluído" ou "excluído" com o MOTIVO (nada é apagado: o dataset fica intacto).
     Saída: output/codebench_manifesto.csv
  2. AMOSTRA — sorteia, entre as incluídas, quantas você pedir (--total N ou --por-questao N),
     com semente fixa (--seed), como no avaliar_juliet.py.
  3. JUIZ + PIPELINE — para cada submissão sorteada:
       a) compila o main.c como um juiz online (sem sanitizers) e roda cada caso de teste com
          limite de tempo, comparando a saída com a esperada -> veredito por caso:
          AC (aceito), WA (resposta errada), RE (erro de execução), TLE (tempo excedido);
          ou CE (erro de compilação) para a submissão inteira;
       b) se algum caso falhou, roda a cascata de detecção (Malha 1 -> Malha 2 -> Malha UBSan ->
          cwe.py, igual à produção) usando a ENTRADA DO CASO QUE FALHOU (prioridade RE > WA > TLE).
     Saídas: output/avaliacao_codebench.csv (1 linha por submissão),
             output/codebench_testes.csv (1 linha por caso de teste),
             output/codebench_historico.csv (1 linha por rodada, acumula).

── Como usar (dentro do contêiner, ver data/codebench/README.md) ──
    python3 avaliar_codebench.py --inventario                 # só o manifesto, não roda código
    python3 avaliar_codebench.py --total 30 --seed 42         # 30 submissões sorteadas
    python3 avaliar_codebench.py --por-questao 2 --seed 7     # 2 por questão
    python3 avaliar_codebench.py --total 50 --analisar todas  # pipeline também nas aceitas
    python3 avaliar_codebench.py --total 40 --veredito reprovadas   # só as NÃO aceitas
    python3 avaliar_codebench.py --por-questao 1 --veredito RE      # 1 travamento por questão

O dataset traz a ÚLTIMA versão de cada aluno, e a maioria é aceita (~86% numa amostra de 251).
Com --veredito, a amostra é completada só com o veredito pedido: as submissões são embaralhadas
pela semente e julgadas uma a uma até atingir o tamanho (o histórico registra quantas foram
julgadas e o veredito de cada uma, para a proporção ficar documentada).

Código de aluno é código não confiável: rode SEMPRE no contêiner Docker sem rede.
"""

import argparse
import collections
import csv
import hashlib
import os
import random
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

from src.malha1_asan import executar_malha_1_asan
from src.malha2_valgrind import executar_malha_2_valgrind
from src.malha_ubsan import executar_malha_ubsan, deve_refinar
from src.llm_client import classificar_erro  # 100% determinística (não chama o LLM)


# ── Critérios do juiz ──────────────────────────────────────────────────────────
# Não sabemos as flags exatas do CodeBench; usamos as mesmas das malhas (-std=gnu11) + -lm
# (math.h: sem -lm, sqrt/pow com argumento variável não linka e viraria "erro de compilação").
FLAGS_JUIZ = ["-std=gnu11", "-lm"]
TEMPO_LIMITE_PADRAO_S = 2.0          # por caso de teste (ajustável com --tempo-limite)
LIMITE_SAIDA_BYTES = 10 * 1024 * 1024  # programa que imprime sem parar é cortado em 10 MB
LIMITE_MEMORIA_BYTES = 1024 ** 3        # 1 GB de memória virtual por execução do juiz
# Entrada de caso de teste que é só um NOME DE ARQUIVO (ex.: "arquivo_1.txt") = questão que lê
# arquivo de dados. Ver data/codebench/README.md.
_RX_NOME_ARQUIVO = re.compile(r"^[\w.-]+\.(?:txt|bin|dat|csv)$")
# Vereditos: AC aceito | WA resposta errada | RE travamento por SINAL (segfault, divisão por zero,
# abort) | EXIT terminou com código ≠ 0 (ex.: "return 1;") | TLE tempo excedido | CE compilação.
# Prioridade para escolher o caso que alimenta o pipeline (e o veredito geral da submissão):
# travamento primeiro (é o foco do módulo), depois resposta errada, depois código de saída ≠ 0,
# depois tempo excedido (o mais lento para as malhas).
_PRIORIDADE_FALHA = ("RE", "WA", "EXIT", "TLE")
VEREDITOS = ("AC", "WA", "RE", "EXIT", "TLE", "CE")


# ══════════════════════════════════════════════════════════════════════════════
# 1. Inventário
# ══════════════════════════════════════════════════════════════════════════════

def _ler_data(pasta):
    """Lê o data.txt ('chave: valor') de uma pasta; {} se não existir."""
    caminho = os.path.join(pasta, "data.txt")
    if not os.path.isfile(caminho):
        return {}
    dados = {}
    with open(caminho, encoding="utf-8", errors="replace") as f:
        for linha in f:
            if ":" in linha:
                chave, valor = linha.split(":", 1)
                dados[chave.strip()] = valor.strip()
    return dados


def _subpastas(pasta):
    return sorted(n for n in os.listdir(pasta)
                  if os.path.isdir(os.path.join(pasta, n)) and not n.startswith("."))


def _casos_de_teste(pasta_questao):
    """[(n, caminho_input, caminho_output)] ordenado por n."""
    pasta = os.path.join(pasta_questao, "test-cases")
    if not os.path.isdir(pasta):
        return []
    casos = []
    for nome in os.listdir(pasta):
        m = re.match(r"^(\d+)\.input\.txt$", nome)
        if m:
            saida = os.path.join(pasta, f"{m.group(1)}.output.txt")
            if os.path.isfile(saida):
                casos.append((int(m.group(1)), os.path.join(pasta, nome), saida))
    return sorted(casos)


def _hash(caminho):
    with open(caminho, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _versao_mais_comum(pastas_alunos, nome):
    """(sha256, caminho) da versão mais comum de `nome` entre as pastas dadas; None se nenhuma tem."""
    versoes, exemplo = collections.Counter(), {}
    for p in pastas_alunos:
        caminho = os.path.join(p, nome)
        if os.path.isfile(caminho):
            h = _hash(caminho)
            versoes[h] += 1
            exemplo.setdefault(h, caminho)
    if not versoes:
        return None
    h, _ = versoes.most_common(1)[0]
    return h, exemplo[h]


def _arquivos_de_dados(pasta_questao, casos, alunos, alunos_mesma_questao):
    """
    Para questão que lê arquivo: {nome: (sha256, caminho)} com a versão MAIS COMUM do arquivo
    entre as pastas dos alunos (a disponibilizada no ambiente; os poucos diferentes são alunos que
    editaram). Ordem de busca: alunos desta questão -> alunos da MESMA questão em outras turmas
    (MEDIDO: "Leitura de arquivo binário" de uma turma não tinha o .bin em nenhum aluno, a da outra
    tinha). Se ninguém no dataset tem o arquivo, ele é INEXISTENTE DE PROPÓSITO e não é fornecido
    (MEDIDO: "arquivo_0.txt" do Palindromo testa a mensagem "Arquivo nao existe"); fica registrado.
    """
    pedidos = set()
    for _, entrada, _ in casos:
        with open(entrada, encoding="utf-8", errors="replace") as f:
            primeira = f.readline().strip()
        if _RX_NOME_ARQUIVO.match(primeira):
            pedidos.add(primeira)
    escolhidos, inexistentes = {}, set()
    for nome in sorted(pedidos):
        achado = (_versao_mais_comum([os.path.join(pasta_questao, a) for a in alunos], nome)
                  or _versao_mais_comum(alunos_mesma_questao, nome))
        if achado:
            escolhidos[nome] = achado
        else:
            inexistentes.add(nome)
    return escolhidos, inexistentes


def _questoes_em_c(raiz):
    """[(d_disc, turma, d_turma, d_lista, questao, p_q, d_q)] de todas as listas em C."""
    questoes = []
    for disc in _subpastas(raiz):
        p_disc = os.path.join(raiz, disc)
        d_disc = _ler_data(p_disc)
        for turma in _subpastas(p_disc):
            p_turma = os.path.join(p_disc, turma)
            d_turma = _ler_data(p_turma)
            for lista in _subpastas(p_turma):
                p_lista = os.path.join(p_turma, lista)
                d_lista = _ler_data(p_lista)
                if d_lista.get("programmingLanguage") != "C":
                    continue  # só listas em C entram no inventário (as outras nem são contadas)
                for questao in _subpastas(p_lista):
                    p_q = os.path.join(p_lista, questao)
                    questoes.append((d_disc, turma, d_turma, d_lista, questao, p_q, _ler_data(p_q)))
    return questoes


def inventariar(raiz):
    """Uma linha por (aluno, questão) de lista em C, com status e motivo."""
    questoes = _questoes_em_c(raiz)
    # A mesma questão (mesmo id) aparece em várias turmas: junta todas as pastas de aluno dela,
    # para achar arquivos de dados que só alunos de outra turma têm.
    alunos_por_id = collections.defaultdict(list)
    for *_, questao, p_q, _ in questoes:
        alunos_por_id[questao] += [os.path.join(p_q, a) for a in _subpastas(p_q) if a != "test-cases"]

    linhas = []
    for d_disc, turma, d_turma, d_lista, questao, p_q, d_q in questoes:
        casos = _casos_de_teste(p_q)
        alunos = [a for a in _subpastas(p_q) if a != "test-cases"]
        dados, inexistentes = (_arquivos_de_dados(p_q, casos, alunos, alunos_por_id[questao])
                               if casos else ({}, set()))
        for aluno in alunos:
            p_a = os.path.join(p_q, aluno)
            arquivos = os.listdir(p_a)
            fontes = [n for n in arquivos if n.endswith((".c", ".h"))]
            subdirs = [n for n in arquivos if os.path.isdir(os.path.join(p_a, n))
                       and n != "__pycache__"]
            if "main.c" not in arquivos:
                motivo = "sem main.c (pasta vazia ou outro nível)"
            elif fontes != ["main.c"] or subdirs:
                motivo = "código em mais de um arquivo ou em subpasta"
            elif not casos:
                motivo = "questão sem casos de teste"
            else:
                motivo = ""
            arquivos_dados = [f"{n}={h[:12]}" for n, (h, _) in dados.items()]
            arquivos_dados += [f"{n}=inexistente (proposital)" for n in sorted(inexistentes)]
            linhas.append({
                "Disciplina": d_disc.get("name", "?"),
                "Turma": f"{d_turma.get('year', '?')}/{d_turma.get('semester', '?')} ({turma})",
                "Lista": d_lista.get("title", "?"),
                "Questão": d_q.get("title", questao),
                "Id Questão": questao,
                "Id Aluno": aluno,
                "Casos de Teste": len(casos),
                "Arquivos de Dados": "; ".join(arquivos_dados) or "-",
                "Status": "excluído" if motivo else "incluído",
                "Motivo": motivo or "-",
                "_pasta_questao": p_q,
                "_pasta_aluno": p_a,
                "_casos": casos,
                "_dados": dados,
            })
    return linhas


# ══════════════════════════════════════════════════════════════════════════════
# 2. Juiz
# ══════════════════════════════════════════════════════════════════════════════

def _limites():
    """preexec_fn: limita memória e tamanho de arquivo de saída do programa do aluno."""
    resource.setrlimit(resource.RLIMIT_AS, (LIMITE_MEMORIA_BYTES, LIMITE_MEMORIA_BYTES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMITE_SAIDA_BYTES, LIMITE_SAIDA_BYTES))


def _normalizar(texto):
    """Comparação flexível: ignora espaços no fim das linhas e linhas vazias no final."""
    linhas = [l.rstrip() for l in texto.replace("\r\n", "\n").split("\n")]
    while linhas and not linhas[-1]:
        linhas.pop()
    return linhas


def julgar(sub, pasta_trabalho, tempo_limite):
    """
    Compila e roda todos os casos. Devolve (veredito_geral, [(n, veredito, detalhe)], erro_compilacao).
    Roda dentro de `pasta_trabalho` (onde ficam os arquivos de dados da questão, se houver).
    """
    binario = os.path.join(pasta_trabalho, "juiz_bin")
    comp = subprocess.run(["gcc", os.path.join(sub["_pasta_aluno"], "main.c"), *FLAGS_JUIZ, "-o", binario],
                          capture_output=True, text=True, errors="replace")
    if comp.returncode != 0:
        return "CE", [], comp.stderr[-500:]

    resultados = []
    for n, entrada, esperado in sub["_casos"]:
        saida_arq = os.path.join(pasta_trabalho, f"saida_{n}.txt")
        with open(entrada, "rb") as fin, open(saida_arq, "wb") as fout:
            try:
                r = subprocess.run([binario], stdin=fin, stdout=fout, stderr=subprocess.DEVNULL,
                                   cwd=pasta_trabalho, timeout=tempo_limite, preexec_fn=_limites)
                codigo = r.returncode
            except subprocess.TimeoutExpired:
                resultados.append((n, "TLE", f"> {tempo_limite}s"))
                continue
        if codigo < 0:
            # Morto por SINAL = travamento de verdade (ex.: -11 SIGSEGV, -8 SIGFPE, -6 SIGABRT).
            resultados.append((n, "RE", f"sinal {-codigo}"))
            continue
        with open(saida_arq, encoding="utf-8", errors="replace") as f:
            obtida = _normalizar(f.read())
        with open(esperado, encoding="utf-8", errors="replace") as f:
            correta = _normalizar(f.read())
        if codigo > 0:
            # Terminou sozinho, mas com código ≠ 0 (ex.: o aluno escreveu "return 1;" no main).
            # Não é travamento nem erro de memória; não sabemos como o CodeBench trata — fica separado.
            ok = "saída correta" if obtida == correta else "saída diferente"
            resultados.append((n, "EXIT", f"código {codigo}, {ok}"))
            continue
        if obtida == correta:
            resultados.append((n, "AC", "-"))
        elif [l for l in obtida if l] == [l for l in correta if l]:
            # Só linhas em branco a mais/a menos: pode ser rigor do NOSSO juiz (não sabemos se o
            # CodeBench ignora isso). Continua WA, mas marcado, para você decidir na análise.
            resultados.append((n, "WA", "só linhas em branco"))
        else:
            resultados.append((n, "WA", "-"))

    vereditos = {v for _, v, _ in resultados}
    if vereditos == {"AC"}:
        geral = "AC"
    else:
        geral = next(v for v in _PRIORIDADE_FALHA if v in vereditos)
    return geral, resultados, ""


# ══════════════════════════════════════════════════════════════════════════════
# 3. Pipeline (mesma cascata da produção: api/runner_analise.py)
# ══════════════════════════════════════════════════════════════════════════════

def rodar_pipeline(sub, entrada, pasta_trabalho):
    """Devolve (ferramenta, status, cwe, nome, linha_sintoma, linha_causa)."""
    fonte = os.path.join(pasta_trabalho, "main.c")      # cópia: as malhas compilam e rodam aqui
    shutil.copy(os.path.join(sub["_pasta_aluno"], "main.c"), fonte)
    flags = ["-lm"]
    cwd_antes = os.getcwd()
    os.chdir(pasta_trabalho)                            # arquivos de dados ficam nesta pasta
    try:
        r = executar_malha_1_asan(fonte, binario_saida=os.path.join(pasta_trabalho, "b_asan"),
                                  entrada=entrada, flags_extra=flags)
        ferramenta = "ASan+GDB"
        if r and r.get("tipo") == "compilacao":
            return "Compilador (gcc)", "erro_compilacao", "-", "-", "-", "-"
        if deve_refinar(r):
            ref = executar_malha_ubsan(fonte, binario_saida=os.path.join(pasta_trabalho, "b_ubsan"),
                                       entrada=entrada, flags_extra=flags, somente_indice=True)
            if ref:
                r, ferramenta = ref, "UBSan (refinando crash)"
        if not r:
            r = executar_malha_2_valgrind(fonte, binario_saida=os.path.join(pasta_trabalho, "b_vg"),
                                          entrada=entrada, flags_extra=flags)
            ferramenta = "Valgrind+vgdb"
        if not r:
            r = executar_malha_ubsan(fonte, binario_saida=os.path.join(pasta_trabalho, "b_ubsan"),
                                     entrada=entrada, flags_extra=flags)
            ferramenta = "UBSan"
        if not r:
            return "Nenhuma", "passou_limpo", "-", "-", "-", "-"
        with open(fonte, encoding="utf-8", errors="replace") as f:
            a = classificar_erro(r["log"], f.read(), "main.c", log_bruto=r["log"])
        return ferramenta, "detectado", a["cwe_id"], a["cwe_nome"], a["linha_sintoma"], a["linha_causa"]
    finally:
        os.chdir(cwd_antes)


# ══════════════════════════════════════════════════════════════════════════════
# Programa principal
# ══════════════════════════════════════════════════════════════════════════════

def _commit_dataset(raiz):
    try:
        r = subprocess.run(["git", "-C", raiz, "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or "-"
    except Exception:
        return "-"


def _gravar_csv(caminho, linhas, modo="w"):
    if not linhas:
        return
    campos = [k for k in linhas[0] if not k.startswith("_")]
    existe = os.path.isfile(caminho) and modo == "a"
    if existe:
        with open(caminho, encoding="utf-8", newline="") as f:
            if next(csv.reader(f), []) != campos:     # cabeçalho mudou: preserva o antigo
                os.replace(caminho, caminho.replace(".csv", f"_ate_{datetime.now():%Y%m%d%H%M%S}.csv"))
                existe = False
    with open(caminho, modo, newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos, extrasaction="ignore")
        if not existe:
            w.writeheader()
        w.writerows(linhas)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--codebench-dir",
                    default=os.environ.get("CODEBENCH_DIR", os.path.expanduser("~/datasets/cb-dataset")),
                    help="Raiz do cb-dataset (padrão: ~/datasets/cb-dataset).")
    ap.add_argument("--inventario", action="store_true", help="Só gera o manifesto e sai (não roda código).")
    ap.add_argument("--total", type=int, help="Quantas submissões sortear (entre as incluídas).")
    ap.add_argument("--por-questao", type=int, help="Quantas submissões sortear POR questão.")
    ap.add_argument("--seed", type=int, default=42, help="Semente do sorteio (reprodutibilidade).")
    ap.add_argument("--tempo-limite", type=float, default=TEMPO_LIMITE_PADRAO_S,
                    help=f"Tempo máximo por caso de teste no juiz, em segundos (padrão {TEMPO_LIMITE_PADRAO_S}).")
    ap.add_argument("--analisar", choices=("falhas", "todas", "nenhuma"), default="falhas",
                    help="Em quais submissões rodar o pipeline: só nas que falharam (padrão), em todas "
                         "(nas aceitas usa o caso 1, para achar erros silenciosos como vazamento) ou em nenhuma.")
    ap.add_argument("--veredito", default="todos",
                    help="Filtro da amostra pelo veredito do juiz: 'todos' (padrão), 'reprovadas' (tudo que "
                         "não é AC) ou lista separada por vírgula, ex.: 'RE,WA'. Com filtro, as submissões são "
                         "embaralhadas pela semente e julgadas uma a uma até completar a amostra.")
    ap.add_argument("--saida-dir", default="./output", help="Pasta dos CSVs (padrão ./output).")
    args = ap.parse_args()

    if not os.path.isdir(args.codebench_dir):
        sys.exit(f"[Erro] Não achei o dataset em '{args.codebench_dir}' (ver data/codebench/README.md).")
    os.makedirs(args.saida_dir, exist_ok=True)

    # ── 1. Inventário ──
    print(f"[Info] Inventariando {args.codebench_dir} ...")
    inventario = inventariar(args.codebench_dir)
    _gravar_csv(os.path.join(args.saida_dir, "codebench_manifesto.csv"), inventario)
    incluidas = [s for s in inventario if s["Status"] == "incluído"]
    motivos = collections.Counter(s["Motivo"] for s in inventario if s["Status"] == "excluído")
    print(f"[Info] Submissões em C: {len(inventario)} | incluídas: {len(incluidas)} | "
          f"excluídas: {len(inventario) - len(incluidas)}")
    for m, n in motivos.most_common():
        print(f"         excluídas por '{m}': {n}")
    print(f"[Info] Manifesto: {os.path.join(args.saida_dir, 'codebench_manifesto.csv')}")
    if args.inventario:
        return

    # ── 2. Amostra (com filtro de veredito opcional) ──
    if not args.total and not args.por_questao:
        sys.exit("[Erro] Diga o tamanho da amostra: --total N ou --por-questao N (ou use --inventario).")
    if args.veredito == "todos":
        aceitos = set(VEREDITOS)
    elif args.veredito == "reprovadas":
        aceitos = set(VEREDITOS) - {"AC"}
    else:
        aceitos = {v.strip().upper() for v in args.veredito.split(",")}
        if not aceitos <= set(VEREDITOS):
            sys.exit(f"[Erro] --veredito: use {', '.join(VEREDITOS)}, 'reprovadas' ou 'todos'.")

    # Ordem determinística: embaralha com a semente; com --por-questao, um grupo por questão.
    rng = random.Random(args.seed)
    if args.por_questao:
        por_q = collections.defaultdict(list)
        for s in incluidas:
            por_q[s["Id Questão"]].append(s)
        grupos = [(q, rng.sample(por_q[q], len(por_q[q])), args.por_questao) for q in sorted(por_q)]
    else:
        grupos = [("todas", rng.sample(incluidas, len(incluidas)), args.total)]
    print(f"\n[Info] Amostra: {'%d por questão' % args.por_questao if args.por_questao else '%d no total' % args.total}"
          f" | veredito: {args.veredito} | seed {args.seed} | juiz {args.tempo_limite}s/caso | "
          f"pipeline: {args.analisar}\n")

    # ── 3. Juiz (+ filtro) + pipeline ──
    linhas, linhas_testes = [], []
    julgadas = 0                      # quantas foram julgadas para completar a amostra (transparência)
    vereditos_julgados = collections.Counter()
    for _, candidatos, cota in grupos:
        pegas = 0
        for sub in candidatos:
            if pegas >= cota:
                break
            inicio = time.time()
            with tempfile.TemporaryDirectory(prefix="cb_") as trab:
                for nome, (_, origem) in sub["_dados"].items():
                    shutil.copy(origem, os.path.join(trab, nome))
                geral, por_caso, erro_comp = julgar(sub, trab, args.tempo_limite)
                julgadas += 1
                vereditos_julgados[geral] += 1
                if geral not in aceitos:
                    continue          # fora do filtro: só conta como julgada
                pegas += 1
                print(f"[{len(linhas) + 1}] {sub['Questão']} | aluno {sub['Id Aluno']}")
                for n, v, det in por_caso:
                    linhas_testes.append({"Id Questão": sub["Id Questão"], "Id Aluno": sub["Id Aluno"],
                                          "Caso": n, "Veredito": v, "Detalhe": det})

                caso_analisado, ver_caso = "-", "-"
                ferramenta, status, cwe, nome, sint, causa = "-", "nao_analisado", "-", "-", "-", "-"
                alvo = None
                if geral not in ("AC", "CE") and args.analisar != "nenhuma":
                    for prioridade in _PRIORIDADE_FALHA:
                        alvo = next(((n, v) for n, v, _ in por_caso if v == prioridade), None)
                        if alvo:
                            break
                elif geral == "AC" and args.analisar == "todas":
                    alvo = (por_caso[0][0], "AC")
                if alvo:
                    caso_analisado, ver_caso = alvo
                    caminho_in = next(e for n, e, _ in sub["_casos"] if n == caso_analisado)
                    with open(caminho_in, encoding="utf-8", errors="replace") as f:
                        entrada = f.read()
                    try:
                        ferramenta, status, cwe, nome, sint, causa = rodar_pipeline(sub, entrada, trab)
                    except Exception as e:  # um caso problemático não derruba a rodada
                        status = f"erro_interno: {type(e).__name__}"

            cont = collections.Counter(v for _, v, _ in por_caso)
            wa = [d for _, v, d in por_caso if v == "WA"]
            duracao = round(time.time() - inicio, 2)
            print(f"      -> veredito {geral} ({dict(cont) or erro_comp[:60]}) | pipeline: {status} {cwe} ({duracao}s)")
            linhas.append({
                **{k: sub[k] for k in ("Disciplina", "Turma", "Lista", "Questão", "Id Questão", "Id Aluno",
                                        "Casos de Teste", "Arquivos de Dados")},
                "Veredito": geral,
                **{v: cont.get(v, 0) for v in ("AC", "WA", "RE", "EXIT", "TLE")},
                # "sim" = TODAS as respostas erradas diferem só em linhas em branco (pode ser rigor do juiz)
                "WA Só Linhas em Branco": ("sim" if wa and all(d == "só linhas em branco" for d in wa)
                                           else "não" if wa else "-"),
                "Caso Analisado": caso_analisado,
                "Veredito do Caso": ver_caso,
                "Ferramenta": ferramenta,
                "Status Pipeline": status,
                "CWE": cwe,
                "Nome CWE": nome,
                "Linha Sintoma": sint,
                "Linha Causa": causa,
                "Tempo (s)": duracao,
            })
    if not linhas:
        sys.exit(f"[Aviso] Nenhuma submissão com veredito {args.veredito} nas {julgadas} julgadas.")

    _gravar_csv(os.path.join(args.saida_dir, "avaliacao_codebench.csv"), linhas)
    _gravar_csv(os.path.join(args.saida_dir, "codebench_testes.csv"), linhas_testes)

    # ── Resumo + histórico ──
    vered = collections.Counter(l["Veredito"] for l in linhas)
    analisadas = [l for l in linhas if l["Status Pipeline"] not in ("nao_analisado",)]
    detect = [l for l in analisadas if l["Status Pipeline"] == "detectado"]
    re_ = [l for l in analisadas if l["Veredito do Caso"] == "RE"]
    re_det = [l for l in re_ if l["Status Pipeline"] == "detectado"]
    resumo = {
        "Data/Hora (UTC)": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "Commit dataset": _commit_dataset(args.codebench_dir),
        "Seed": args.seed, "Total": args.total or "-", "Por Questão": args.por_questao or "-",
        "Tempo Limite (s)": args.tempo_limite, "Analisar": args.analisar, "Filtro Veredito": args.veredito,
        "Julgadas": julgadas,
        **{f"Julgadas {v}": vereditos_julgados.get(v, 0) for v in VEREDITOS},
        "Submissões": len(linhas),
        **{f"Veredito {v}": vered.get(v, 0) for v in VEREDITOS},
        "Pipeline Rodou": len(analisadas), "Pipeline Detectou": len(detect),
        "Casos RE": len(re_), "RE Detectados": len(re_det),
    }
    _gravar_csv(os.path.join(args.saida_dir, "codebench_historico.csv"), [resumo], modo="a")

    print("\n" + "=" * 60)
    print("RESUMO")
    print("=" * 60)
    print(f"Julgadas: {julgadas} ({dict(vereditos_julgados)}) | na amostra: {len(linhas)} ({dict(vered)})")
    print(f"Pipeline rodou em {len(analisadas)} e detectou algo em {len(detect)}")
    if re_:
        print(f"Cobertura em erro de execução (RE): {len(re_det)}/{len(re_)} "
              f"({100 * len(re_det) / len(re_):.1f}%)")
    cwes = collections.Counter(l["CWE"] for l in detect)
    if cwes:
        print("CWEs encontrados:", ", ".join(f"{c}: {n}" for c, n in cwes.most_common()))
    print(f"\n[Info] CSVs em {args.saida_dir}: avaliacao_codebench.csv, codebench_testes.csv, "
          f"codebench_historico.csv, codebench_manifesto.csv")


if __name__ == "__main__":
    main()
