import requests  # Biblioteca para fazer requisições HTTP (chamar a API do LLM)
import json      # Para serializar/desserializar dados no formato JSON
import sys       # Importado para uso futuro (ex: sys.exit em erros fatais)
import time      # Para backoff entre tentativas de retry

# Endereço da API do LLM rodando localmente (ex: Ollama na porta padrão 11434)
URL_LLM_LOCAL = "http://172.30.0.1:11434/api/generate"

# Nome do modelo que será carregado e consultado pelo Ollama
NOME_MODELO = "qwen2.5-coder:7b"


def _chamar_llm(prompt, tentativa=1):
    """
    Executa uma chamada ao Ollama e retorna o texto completo gerado.
    Retorna string vazia se o servidor não gerar nenhum token.
    """
    resposta = requests.post(URL_LLM_LOCAL, json={
        "model": NOME_MODELO,
        "prompt": prompt,
        "stream": True,
        "format": "json"
    }, stream=True, timeout=120)

    texto_completo = ""
    print(f"  -> [IA Analisando] (tentativa {tentativa}): \n", end="", flush=True)

    for linha in resposta.iter_lines():
        if linha:
            pedaco_json = json.loads(linha.decode('utf-8'))
            pedaco_texto = pedaco_json.get("response", "")
            print(pedaco_texto, end="", flush=True)
            texto_completo += pedaco_texto

    print("\n")
    return texto_completo


def _sanitizar(texto):
    """Remove blocos markdown e espaços extras que alguns modelos inserem."""
    return (
        texto.strip()
        .removeprefix("```json")
        .removeprefix("```")
        .removesuffix("```")
        .strip()
    )


def classificar_erro(log_limpo, codigo_fonte="", max_tentativas=3):
    """
    Envia o log de erro e o código-fonte original para o LLM local
    e retorna um dicionário Python com a classificação forense do erro.

    Retry automático: se o servidor retornar resposta vazia ou JSON inválido,
    o sistema tenta novamente até `max_tentativas` vezes com backoff exponencial
    (1s, 2s, 4s). Isso cobre sobrecarga momentânea do Ollama sem travar o pipeline.

    O código-fonte é opcional (default "") para manter compatibilidade,
    mas quando fornecido enriquece significativamente a análise da IA:
    a IA consegue ver a declaração das variáveis, o tipo, o escopo e
    o contexto ao redor da linha do erro — não apenas o backtrace.
    """
    if codigo_fonte:
        secao_codigo = f"""
        Código-Fonte do Programa:
        ```c
        {codigo_fonte}
        ```
            """
    else:
        secao_codigo = ""

    prompt = f"""
    Você é um classificador forense de erros em C. Analise o log e o código abaixo e retorne APENAS um objeto JSON válido.

    Log do Depurador:
    {log_limpo}
    Código-Fonte do Programa:
    {secao_codigo}
    Formato OBRIGATÓRIO (não inclua formatação markdown ou texto fora do JSON):
    {{
        "tipo_erro": "Nome técnico do erro (ex: stack-buffer-overflow, uninitialized-value, memory-leak)",
        "linha_ocorrencia": "Número da linha onde o erro foi detectado pelo depurador",
        "variaveis_envolvidas": "Variáveis citadas no log e seus valores (ex: i=5, contador=0). Para ponteiros, use nome* (ex: vetor*, cabeca*). Liste apenas o que aparece explicitamente no log.",
        "causa_raiz": "O que realmente causou o erro (ex: 'ponteiro vetor* alocado em malloc() nunca foi liberado', 'estrutura No* com campo prox* também alocado mas não liberado', 'acesso ao índice 5 em array de tamanho 5')",
        "descricao_curta": "Explicação em 1 frase curta do problema"
    }}
    """

    ultimo_erro = None

    for tentativa in range(1, max_tentativas + 1):
        try:
            texto_completo = _chamar_llm(prompt, tentativa)

            # Resposta vazia: Ollama não gerou nenhum token (sobrecarga/timeout interno)
            if not texto_completo.strip():
                raise ValueError("Ollama retornou resposta vazia (nenhum token gerado).")

            sanitizado = _sanitizar(texto_completo)
            return json.loads(sanitizado)

        except (json.JSONDecodeError, ValueError) as e:
            ultimo_erro = e
            if tentativa < max_tentativas:
                espera = 2 ** (tentativa - 1)  # backoff: 1s, 2s, 4s
                print(f"  [Retry {tentativa}/{max_tentativas}] {str(e)} — aguardando {espera}s...")
                time.sleep(espera)

        except Exception as e:
            # Falha de rede, timeout de conexão, servidor offline, etc.
            ultimo_erro = e
            if tentativa < max_tentativas:
                espera = 2 ** (tentativa - 1)
                print(f"  [Retry {tentativa}/{max_tentativas}] Erro de rede: {str(e)} — aguardando {espera}s...")
                time.sleep(espera)

    # Todas as tentativas esgotadas
    print(f"\n[Aviso] IA falhou após {max_tentativas} tentativas. Último erro: {str(ultimo_erro)}")
    return {
        "tipo_erro": "Falha no Pipeline",
        "linha_ocorrencia": "-",
        "variaveis_envolvidas": "-",
        "causa_raiz": "-",
        "descricao_curta": f"LLM não respondeu após {max_tentativas} tentativas: {str(ultimo_erro)}"
    }