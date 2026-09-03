#include <stdio.h>
#include <stdlib.h>

// Função com complexidade O(log N)
int busca_binaria(int *v, int esq, int dir, int chave) {
    while (esq <= dir) {
        int meio = esq + (dir - esq) / 2;
        
        if (v[meio] == chave) {
            return meio;
        }
        if (v[meio] < chave) {
            esq = meio + 1;
        } else {
            dir = meio - 1;
        }
    }
    return -1;
}

int main(void) {
    int n;

    printf("Tamanho do vetor: ");
    scanf("%d", &n);

    if (n <= 0) {
        fprintf(stderr, "Tamanho inválido.\n");
        return 1;
    }

    int *v = malloc(n * sizeof(int));
    if (!v) {
        fprintf(stderr, "Erro de alocação.\n");
        return 1;
    }

    printf("Digite os %d elementos:\n", n);
    for (int i = 0; i < n; i++) {
        scanf("%d", &v[i]);
    }

    // Como o vetor gerado é [1, 2, ..., n], buscamos pelo valor 'n'
    // para garantir o pior caso/caso base da busca binária que leva log N passos.
    int indice = busca_binaria(v, 0, n - 1, n);

    printf("Elemento encontrado no índice: %d\n", indice);

    free(v);
    return 0;
}