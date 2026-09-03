#include <stdio.h>
#include <stdlib.h>

// Troca dois elementos
void swap(int *a, int *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

// Partição: escolhe o pivô (último elemento) e reorganiza o vetor
int particionar(int *v, int esq, int dir) {
    int meio = esq + (dir - esq) / 2;
    swap(&v[meio], &v[dir]);   // move o pivô para o final ANTES do loop
    int pivo = v[dir];
    int i = esq - 1;

    for (int j = esq; j < dir; j++) {
        if (v[j] <= pivo) {
            i++;
            swap(&v[i], &v[j]);
        }
    }
    swap(&v[i + 1], &v[dir]);
    return i + 1;
}

// Quick Sort recursivo — O(n log n) médio, O(n²) pior caso
void quicksort(int *v, int esq, int dir) {
    if (esq < dir) {
        int p = particionar(v, esq, dir);
        quicksort(v, esq, p - 1);
        quicksort(v, p + 1, dir);
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

    quicksort(v, 0, n - 1);

    printf("Vetor ordenado:\n");
    for (int i = 0; i < n; i++) {
        printf("%d%c", v[i], i < n - 1 ? ' ' : '\n');
    }

    free(v);
    return 0;
}