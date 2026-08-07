#include <stdio.h>
#include <stdlib.h>

typedef struct No {
    int dado;
    struct No* prox;
} No;

No* criar_no(int valor) {
    No* novo = (No*)malloc(sizeof(No));
    if (!novo) { fprintf(stderr, "Erro de alocacao\n"); exit(1); }
    novo->dado = valor;
    novo->prox = NULL;
    return novo;
}

void inserir_inicio(No** cabeca, int valor) {
    No* novo = criar_no(valor);
    novo->prox = *cabeca;
    *cabeca = novo;
}

void inserir_fim(No** cabeca, int valor) {
    No* novo = criar_no(valor);
    if (!*cabeca) { *cabeca = novo; return; }
    No* atual = *cabeca;
    while (atual->prox) atual = atual->prox;
    atual->prox = novo;
}

void remover(No** cabeca, int valor) {
    No* atual = *cabeca;
    No* anterior = NULL;
    while (atual && atual->dado != valor) {
        anterior = atual;
        atual = atual->prox;
    }
    if (!atual) return;
    if (!anterior) *cabeca = atual->prox;
    else anterior->prox = atual->prox;
    free(atual);
}

void imprimir(No* cabeca) {
    while (cabeca) {
        printf("%d -> ", cabeca->dado);
        cabeca = cabeca->prox;
    }
    printf("NULL\n");
}

void liberar(No** cabeca) {
    No* atual = *cabeca;
    while (atual) {
        No* temp = atual;
        atual = atual->prox;
        free(temp);
    }
    *cabeca = NULL;
}

int main() {
    No* lista = NULL;

    inserir_fim(&lista, 10);
    inserir_fim(&lista, 20);
    inserir_fim(&lista, 30);
    inserir_inicio(&lista, 5);
    imprimir(lista);       // 5 -> 10 -> 20 -> 30 -> NULL

    remover(&lista, 20);
    imprimir(lista);       // 5 -> 10 -> 30 -> NULL

    liberar(&lista);
    return 0;
}