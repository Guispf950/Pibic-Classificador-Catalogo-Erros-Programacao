"""
sandbox.py — Wrapper de "sandbox" em Docker para rodar a DETECÇÃO com segurança.
================================================================================
POR QUE ISSO EXISTE:
  O código do aluno é CÓDIGO NÃO CONFIÁVEL. Rodá-lo direto na máquina que hospeda a
  API é perigoso. A solução padrão é executar cada submissão dentro de um "sandbox":
  um ambiente ISOLADO e DESCARTÁVEL, com limites de recursos. Usamos um CONTÊINER
  Docker por submissão — criado, usado e destruído (--rm).

O QUE RODA AQUI DENTRO:
  A DETECÇÃO (Malha 1 ASan+GDB e Malha 2 Valgrind), via runner_analise.py. O LLM
  NÃO roda aqui (o contêiner tem --network none e não alcança o Ollama). A
  classificação e o feedback acontecem no HOST (ver pipeline_adapter.py).

MODOS (variável de ambiente MODO_SANDBOX):
  • "docker" -> contêiner de verdade (precisa da imagem construída).
  • qualquer outro valor -> modo MOCK: não executa nada, devolve um resultado de
    exemplo (deixa a API testável sem Docker).
"""

import os
import json
import subprocess
import tempfile

# "docker" = usa contêiner de verdade; qualquer outro valor = modo mock (sem executar).
MODO_SANDBOX = os.environ.get("MODO_SANDBOX", "mock")
IMAGEM = os.environ.get("IMAGEM_ANALISE", "analise-mem:latest")   # nome da imagem Docker
TIMEOUT_S = int(os.environ.get("SANDBOX_TIMEOUT_S", "180"))        # teto (heurística de 3 min)

# Marcador que o runner_analise.py imprime antes do JSON de resultado (ver aquele arquivo).
MARCADOR = "===RESULTADO_JSON==="


def _resultado_mock() -> dict:
    """Resultado de exemplo quando o sandbox está desligado (MODO_SANDBOX != docker)."""
    return {
        "erro_encontrado": True,
        "ferramenta": "MOCK (sandbox desligado)",
        "categoria": "memoria",
        "log_bruto": "==MOCK== defina MODO_SANDBOX=docker para rodar a detecção real",
        "log_limpo": "==MOCK== log de exemplo",
    }


def _extrair_json(saida: str) -> dict:
    """
    Pega o JSON que o runner imprime DEPOIS do MARCADOR (os prints das malhas ficam
    antes e são descartados). Se não achar, devolve um resultado de erro explícito.
    """
    if MARCADOR in saida:
        depois = saida.split(MARCADOR, 1)[1].strip()
        # o JSON é a 1ª linha não-vazia após o marcador
        for linha in depois.splitlines():
            linha = linha.strip()
            if linha:
                try:
                    return json.loads(linha)
                except json.JSONDecodeError:
                    break
    return {
        "erro_encontrado": False,
        "ferramenta": "Falha ao ler resultado do contêiner",
        "categoria": "erro_sandbox",
        "log_bruto": saida[-2000:],   # últimos 2000 chars ajudam a depurar
        "log_limpo": "",
    }


def rodar_em_sandbox(codigo: str, entrada: str, nome_arquivo: str = "submissao.c") -> dict:
    """
    Executa a DETECÇÃO do erro dentro de um contêiner isolado e devolve um DICT:
        {erro_encontrado, ferramenta, categoria, log_bruto, log_limpo}
    (é isso que o pipeline_adapter.analisar consome para chamar o classificador).
    """
    if MODO_SANDBOX != "docker":
        return _resultado_mock()

    # 1) Escreve o código do aluno num diretório temporário do host. Esse diretório
    #    é "montado" (só-leitura) dentro do contêiner para as ferramentas o enxergarem.
    with tempfile.TemporaryDirectory() as tmp:
        caminho_host = os.path.join(tmp, nome_arquivo)
        with open(caminho_host, "w", encoding="utf-8") as f:
            f.write(codigo)

        # Grava a ENTRADA (o caso de teste do CodeBench) como entrada.in NO MESMO
        # diretório montado. O runner_analise a lê de /work/entrada.in e a usa como
        # stdin AUTORITATIVO — é assim que a entrada chega SEMPRE junto com o código,
        # sem depender de heurística. Gravamos sempre (mesmo vazia).
        with open(os.path.join(tmp, "entrada.in"), "w", encoding="utf-8") as f:
            f.write(entrada or "")

        # 2) Monta o comando `docker run` com as TRAVAS DE SEGURANÇA (cada flag explicada):
        comando = [
            "docker", "run",
            "--rm",                        # remove o contêiner ao terminar (descartável)
            "--network", "none",           # SEM rede (impede o código "ligar pra fora")
            "--memory", "512m",            # teto de memória (Valgrind consome bastante)
            "--cpus", "1",                 # no máximo 1 CPU
            "--pids-limit", "128",         # limite de processos (barra "fork bomb")
            "--read-only",                 # sistema de arquivos só-leitura...
            "--tmpfs", "/tmp:size=128m,exec",  # ...exceto /tmp (compilar/rodar precisa de exec)
            "--user", "1000:1000",         # roda como usuário SEM privilégios (não-root)
            # GDB e Valgrind precisam de ptrace; o seccomp padrão do Docker o bloqueia.
            # SYS_PTRACE libera SÓ o ptrace (mais restrito que --privileged).
            "--cap-add", "SYS_PTRACE",
            "--security-opt", "seccomp=unconfined",  # ASan/Valgrind usam syscalls que o
                                                     # perfil seccomp padrão barra
            "-v", f"{tmp}:/work:ro",       # monta o código do aluno em /work (só-leitura)
            IMAGEM,                        # a imagem a usar (ver Dockerfile.analise)
            "/work/" + nome_arquivo,       # argumento: qual arquivo analisar
        ]

        # 3) Executa com TIMEOUT. A entrada NÃO vai pelo stdin do `docker run` (que sobe
        #    sem -i e o ignoraria); ela viaja pelo arquivo entrada.in montado em /work,
        #    que o runner lê e repassa às malhas como stdin autoritativo.
        try:
            proc = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            return {
                "erro_encontrado": True,
                "ferramenta": "Timeout",
                "categoria": "timeout",
                "log_bruto": f"==TIMEOUT== execução excedeu {TIMEOUT_S}s (loop ou espera de entrada)",
                "log_limpo": f"Execução excedeu {TIMEOUT_S}s (possível loop infinito).",
            }
        except FileNotFoundError:
            # `docker` não está instalado/no PATH.
            return {
                "erro_encontrado": False,
                "ferramenta": "Docker indisponível",
                "categoria": "erro_sandbox",
                "log_bruto": "Comando 'docker' não encontrado. Instale o Docker ou use MODO_SANDBOX=mock.",
                "log_limpo": "",
            }

        # 4) O runner imprime prints (ruído) + o JSON após o marcador. Extraímos o JSON.
        #    stderr entra junto porque um erro do docker/imagem costuma sair por lá.
        return _extrair_json(proc.stdout + "\n" + proc.stderr)
