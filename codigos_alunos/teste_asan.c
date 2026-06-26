#include <stdio.h>

void preencher_notas() {
    int notas[5] = {10, 20, 30, 40, 50}; // Índices válidos: 0 a 4
    
    // ERRO: O laço vai até i <= 5. Na última iteração (i=5), invade a memória!
    for (int i = 0; i <= 5; i++) {
        printf("Nota %d: %d\n", i, notas[i]);
    }
}

int main() {
    preencher_notas();
    return 0;
}
