# Experimentos

Cada experimento é uma pasta `AAAA-MM_descricao/` contendo tudo o que é preciso para
**reproduzir** e **entender** aquela rodada. A ideia: abrir a pasta meses depois e saber
o que foi testado, com qual código, e o que se concluiu — sem depender da memória.

## Como criar um novo experimento

1. Copie `TEMPLATE/` para `AAAA-MM_descricao/` (ex.: `2026-07_inline-vs-numerica/`).
2. Anote o **hash do commit** que você vai usar:
   ```bash
   git rev-parse --short HEAD
   ```
3. Rode o pipeline no(s) modo(s) desejado(s):
   ```bash
   ANOTACAO_MODO=numerica python orquestrador.py
   ```
4. Copie o catálogo gerado (`output/catalogo_erros_codebench.csv`) para dentro da pasta do
   experimento como `resultados_<modo>.csv`.
5. Preencha o `README.md` do experimento (hipótese, condições, métrica, conclusão).

## A variável dos experimentos de anotação (ablação estilo FLAME)

Controlada por `ANOTACAO_MODO` (variável de ambiente):

| Modo | O que o LLM recebe |
|---|---|
| `inline` | Código **anotado** com `// @@` nas linhas do erro (padrão; hipótese: melhor). |
| `numerica` | Código **original** + as linhas do erro em **texto** (o "FLAME_num"). |
| `nenhuma` | Código **original**, **sem** dica de linha (baseline). |

**Só isso muda entre as condições** — todo o resto do pipeline (detecção, veredito, esquema
JSON, regras do prompt) é idêntico, para a comparação ser justa.

## O que este experimento mede (nuance importante)

Neste pipeline a **localização** do erro é determinística (vem do ASan/Valgrind, não do LLM).
Logo, a ablação de anotação mede a **qualidade da classificação/explicação** do LLM (o
`tipo_erro`, a `causa_raiz`, a `descricao_curta`) sob cada representação — não a acurácia de
localização do LLM (como no FLAME original, onde é o LLM que localiza). Se quiser replicar a
ablação de *localização* do FLAME, é preciso um modo em que o LLM devolva a linha e ela seja
comparada a um gabarito — peça que isso é fácil de adicionar.
