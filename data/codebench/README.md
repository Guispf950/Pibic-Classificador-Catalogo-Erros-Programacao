# Dataset CodeBench (cb-dataset) — procedência

Submissões **reais e anonimizadas** de alunos no CodeBench (UFAM), compartilhadas pelo orientador
(Prof. David Fernandes). O dataset **não fica no projeto**: mora no WSL, em `~/datasets/cb-dataset/`,
fora da pasta sincronizada pelo Google Drive e fora do git. Esta pasta guarda só este README.
O `avaliar_codebench.py` procura em `~/datasets/cb-dataset` por padrão (`--codebench-dir` ou
`CODEBENCH_DIR` mudam isso).

## Origem

| Campo | Valor |
|---|---|
| Fonte | https://github.com/dbfernandes/cb-dataset (público) |
| Commit | `6886e48205b101c62b703d5c4c6b2725c44c220d` (17/09/2026) |
| Tamanho | 42.926 arquivos (sem o `.git`) |
| Baixado em | 27/10/2026 (`git clone --depth 1`) |
| Disciplinas | Algoritmos e Estruturas de Dados; AED I; AED II |
| Listas | 117 no total: 68 em C, 47 em Python, 1 em Go, 1 em Haskell |

## Como restaurar

```bash
mkdir -p ~/datasets && cd ~/datasets
git clone https://github.com/dbfernandes/cb-dataset.git
cd cb-dataset && git checkout 6886e48205b101c62b703d5c4c6b2725c44c220d
```

## Estrutura

Cinco níveis de pasta, cada um com um `data.txt` (`chave: valor`):

```
<disciplina>/                 data.txt: name
  <turma>/                    data.txt: id, teacher, code, year, semester
    <lista>/                  data.txt: title, programmingLanguage, type, start, end
      <questão>/              data.txt: title, correctionMode, type
        statement.html        enunciado
        tips.html             dicas (às vezes vazio)
        test-cases/           N.input.txt / N.output.txt (entrada e saída esperada do professor)
        <aluno>/              id anonimizado (o mesmo id aparece em várias questões)
          main.c | main.py    código do aluno (uma versão por aluno e questão)
          main                binário compilado — NUNCA executar (sempre recompilar do main.c)
```

## O que NÃO tem (e como contornamos)

- **Veredito** (aceito/erro): não vem no dataset. O `avaliar_codebench.py` calcula o próprio
  veredito: compila o `main.c`, roda cada caso de teste e compara com a saída esperada.
- **Histórico e datas** das submissões: só há uma versão por aluno e questão.
- **Arquivos de dados** de questões que leem arquivo (ex.: "Palindromo", "Leitura de arquivo
  binário"): o caso de teste traz só o NOME do arquivo. Os arquivos aparecem nas pastas de alguns
  alunos (ex.: `arquivo_1.txt` idêntico em 53 alunos), o que indica a versão disponibilizada no
  ambiente. Usamos a versão mais comum entre os alunos da questão (hash registrado no CSV); sem
  nenhuma cópia, a submissão é excluída com motivo.

## Cuidados

- Código de terceiros: compilar e executar só no contêiner Docker sem rede.
- LGPD: ids anonimizados, mas comentários podem ter dados pessoais. Processar só localmente;
  nunca enviar código a API externa.
