import requests  # Biblioteca para fazer requisições HTTP (chamar a API do LLM)
import json      # Para serializar/desserializar dados no formato JSON
import sys       # Importado para uso futuro (ex: sys.exit em erros fatais)

# Endereço da API do LLM rodando localmente (ex: Ollama na porta padrão 11434)
URL_LLM_LOCAL = "http://192.168.0.105:11434/api/generate"

# Nome do modelo que será carregado e consultado pelo Ollama
NOME_MODELO = "qwen2.5-coder:7b"


def classificar_erro(log_limpo, codigo_fonte=""):
    """
    Envia o log de erro e o código-fonte original para o LLM local
    e retorna um dicionário Python com a classificação forense do erro.
    
    O código-fonte é opcional (default "") para manter compatibilidade,
    mas quando fornecido enriquece significativamente a análise da IA:
    a IA consegue ver a declaração das variáveis, o tipo, o escopo e
    o contexto ao redor da linha do erro — não apenas o backtrace.
    """

    # Bloco de código-fonte incluído no prompt apenas se foi fornecido.
    # Separado em variável para não poluir o f-string principal.
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
    try:
        resposta = requests.post(URL_LLM_LOCAL, json={
            "model": NOME_MODELO,
            "prompt": prompt,
            "stream": True,
            "format": "json"
        }, stream=True, timeout=120)

        texto_completo = ""

        print("  -> [IA Analisando]: \n", end="", flush=True)

        for linha in resposta.iter_lines():
            if linha:
                pedaco_json = json.loads(linha.decode('utf-8'))
                pedaco_texto = pedaco_json.get("response", "")
                print(pedaco_texto, end="", flush=True)
                texto_completo += pedaco_texto

        print("\n")

        # ── Sanitização antes do parse ────────────────────────────────────────────────
        # Alguns modelos retornam o JSON envolto em blocos markdown (```json ... ```)
        # ou com espaços/quebras de linha extras. strip() e removeprefix/suffix limpam isso.
        # Sem essa etapa, o json.loads() lança JSONDecodeError mesmo com JSON válido dentro.
        texto_completo = texto_completo.strip()
        texto_completo = (
            texto_completo
            .removeprefix("```json")  # Remove abertura de bloco markdown com linguagem
            .removeprefix("```")      # Remove abertura de bloco markdown simples
            .removesuffix("```")      # Remove fechamento de bloco markdown
            .strip()                  # Remove espaços/quebras que ficaram após remover os blocos
        )

        # Converte o JSON sanitizado em dicionário Python para uso no CSV
        return json.loads(texto_completo)

    except json.JSONDecodeError as e:
        # Erro específico de JSON malformado: loga o conteúdo recebido para facilitar debug
        print(f"\n[Aviso] JSON inválido retornado pela IA: {str(e)}")
        print(f"  [DEBUG] Primeiros 300 chars recebidos: {repr(texto_completo[:300])}")
        return {
            "tipo_erro": "Falha no Pipeline",
            "linha_ocorrencia": "-",
            "variaveis_envolvidas": "-",
            "descricao_curta": f"JSON inválido: {str(e)}"
        }

    except Exception as e:
        # Captura falhas de rede, timeout, servidor offline, etc.
        print(f"\n[Aviso] Falha ao processar a resposta da IA: {str(e)}")
        return {
            "tipo_erro": "Falha no Pipeline",
            "linha_ocorrencia": "-",
            "variaveis_envolvidas": "-",
            "descricao_curta": "Erro na comunicação com o LLM local."
        }