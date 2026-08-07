#include <stdio.h>
#include <stdlib.h>

void bubbleSort(int *arr, int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}
int main() {
    int n = 1000; // 1 mil elementos é suficiente para forçar a CPU num O(N^2)
    int *vetor = (int *)malloc(n * sizeof(int));

    if (vetor == NULL) {
        printf("Erro de alocacao\n");
        return 1;
    }

    // Preenche vetor
    for (int i = 0; i < n; i++) {
        vetor[i] = rand() % 1000;
    }

    // Ordena
    bubbleSort(vetor, n);
    // Simulando que o aluno esqueceu de dar o free. O Memcheck vai achar isso.
    // free(vetor); 
    return 0;
}
