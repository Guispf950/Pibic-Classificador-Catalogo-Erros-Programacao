# Juliet Test Suite for C/C++ v1.3 — procedência

Dataset de **validação do módulo de detecção e classificação** (Goal G1). O dataset **não fica
no projeto**: mora no WSL, em `~/datasets/juliet/` (zip + `C/` extraído), fora da pasta
sincronizada pelo Google Drive e fora do git. Esta pasta guarda só este README de procedência.
O `avaliar_juliet.py` procura em `~/datasets/juliet/C` por padrão (`--juliet-dir` ou `JULIET_DIR`
mudam isso). Movido para lá em 27/10/2026 (SHA-256 conferido; 106.093 arquivos em `C/`).

## Origem

| Campo | Valor |
|---|---|
| Fonte | NIST SARD — https://samate.nist.gov/SARD/test-suites/112 |
| Arquivo | `2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip` (salvo aqui como `juliet-test-suite-c-cpp-v1.3.zip`) |
| Tamanho | 152.957.342 bytes (≈146 MB); extraído ≈464 MB, 106.316 arquivos |
| SHA-256 | `ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb` |
| Autor / licença | NSA Center for Assured Software / domínio público (CC0) |
| Baixado em | 30/09/2026 (rebaixado em 12/10/2026, mesmo hash) |

## Como restaurar

```bash
mkdir -p ~/datasets/juliet && cd ~/datasets/juliet
curl -L -o juliet-test-suite-c-cpp-v1.3.zip \
  https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
sha256sum juliet-test-suite-c-cpp-v1.3.zip   # deve bater com o SHA-256 acima
unzip -q juliet-test-suite-c-cpp-v1.3.zip    # cria C/ (testcases/, testcasesupport/, manifest.xml)
```

> **Não guarde em pasta temporária.** Os arquivos do Juliet têm data de 2017 e o limpador
> automático do Windows apagou a primeira cópia, que estava em `AppData\Local\Temp`.

## O que tem e como usamos

- `C/manifest.xml`: para cada caso, o arquivo, a **linha do defeito** e o **CWE** esperado.
  A linha não tem semântica fixa: em alguns CWEs marca onde o erro aparece (ex.: o uso após
  o `free` no CWE-416), em outros onde nasce (ex.: o 1º `free` no CWE-415).
- Cada caso tem versão com erro (`bad`) e corrigida (`good`), selecionadas pelos guardas
  `OMITGOOD` / `OMITBAD`; o `main` só existe com `-DINCLUDEMAIN`. Os casos dependem de
  `C/testcasesupport/` (`std_testcase.h`, `io.c`).
- Só os casos **em C** servem ao pipeline (compila C). Nos CWEs do catálogo há ~8,6 mil
  casos em C de arquivo único e sem entrada externa; os demais são C++, multi-arquivo ou
  dependem de socket/arquivo.
- **Regra de equivalência de CWE** (decidida em 10/2026): um diagnóstico conta como acerto se
  o CWE devolvido pelo `src/cwe.py` for igual ao rótulo do Juliet ou **ancestral** dele na
  hierarquia do MITRE (View-1000). Ex.: rótulo 122 e resposta 787 = acerto. Reportar também
  a versão estrita (só igualdade).
- Código sintético: o desempenho no Juliet **não** é a acurácia em código de aluno. Reportar
  separado do conjunto real do CodeBench.
