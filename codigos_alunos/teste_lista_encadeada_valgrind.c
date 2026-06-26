#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Estrutura básica do nó da lista
typedef struct No {
    int valor;
    struct No *proximo;
} No;

// Função para inserir no início (O(1))
No* inserir(No *inicio, int valor) {
    No *novo = (No*)malloc(sizeof(No));
    if (novo == NULL) return inicio; // Falha na alocação
    
    novo->valor = valor;
    novo->proximo = inicio;
    return novo;
}

// Função de busca (O(n))
int buscar(No *inicio, int alvo) {
    No *atual = inicio;
    while (atual != NULL) {
        if (atual->valor == alvo) return 1; // Encontrou
        atual = atual->proximo;
    }
    return 0; // Não encontrou
}

// Função para o Valgrind não acusar erro
void liberar_lista(No *inicio) {
    No *atual = inicio;
    while (atual != NULL) {
        No *proximo = atual->proximo;
        free(atual);
        atual = proximo;
    }
}

int main() {
    No *minha_lista = NULL;
    srand(time(NULL));

    // 1. Inserir 1000 elementos
    for (int i = 0; i < 1000; i++) {
        minha_lista = inserir(minha_lista, rand() % 5000);
    }

    // 2. Buscar um número aleatório
    int alvo = 2500;
    if (buscar(minha_lista, alvo)) {
        printf("Elemento %d encontrado!\n", alvo);
    } else {
        printf("Elemento %d nao esta na lista.\n", alvo);
    }

    // 3. Se comentar a linha abaixo o Valgrind vai reclamar de leak
    // liberar_lista(minha_lista);

    return 0;
}
