#include <stdio.h>
#include <stdlib.h>

// Função com complexidade O(N)
int encontrar_maximo(int *v, int n) {
    int max = v[0];
    for (int i = 1; i < n; i++) {
        if (v[i] > max) {
            max = v[i];
        }
    }
    return max;
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

    // Executa a função O(N)
    int maximo = encontrar_maximo(v, n);

    printf("Maior elemento: %d\n", maximo);

    free(v);
    return 0;
}