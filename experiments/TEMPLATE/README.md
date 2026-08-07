# <Título do experimento>

- **Data:** AAAA-MM-DD
- **Hipótese / pergunta:** <o que você espera descobrir>
- **Condições comparadas:** <ex.: inline vs numerica vs nenhuma>
- **Commit do código:** <hash — `git rev-parse --short HEAD`>
- **Dataset:** <quais submissões / quantas / de onde>
- **Modelo:** <ex.: qwen2.5-coder:7b, temperatura 0.3>
- **Como rodar:**
  ```bash
  ANOTACAO_MODO=<modo> python orquestrador.py
  # depois: copiar output/catalogo_erros_codebench.csv -> resultados_<modo>.csv
  ```
- **Métrica:** <o que foi medido — ex.: % de acerto de tipo_erro vs gabarito; qualidade da causa_raiz>

## Arquivos desta pasta

- `resultados_inline.csv`, `resultados_numerica.csv`, ... — catálogos de cada condição.
- (opcional) `analise.ipynb` / `analise.py` — o que agrega e compara os resultados.

## Resultados

<tabela / números>

## Conclusão

<o que aprendeu; se confirma ou não a hipótese>
