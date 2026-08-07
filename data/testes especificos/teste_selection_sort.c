#include <stdio.h>
#include <stdlib.h>

// Troca dois elementos
void swap(int *a, int *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

// Função com complexidade O(N²) estrito
void selection_sort(int *v, int n) {
    for (int i = 0; i < n - 1; i++) {
        int min_idx = i;
        for (int j = i + 1; j < n; j++) {
            if (v[j] < v[min_idx]) {
                min_idx = j;
            }
        }
        if (min_idx != i) {
            swap(&v[min_idx], &v[i]);
        }
    }
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

    // Executa a ordenação O(N²)
    selection_sort(v, n);

    printf("Vetor ordenado:\n");
    for (int i = 0; i < n; i++) {
        printf("%d%c", v[i], i < n - 1 ? ' ' : '\n');
    }

    free(v);
    return 0;
}