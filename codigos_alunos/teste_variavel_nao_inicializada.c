#include <stdio.h>

int main() {
    int contador; // ERRO: Variável declarada, mas não inicializada.
    
    // O C vai pegar o lixo de memória que estiver na Stack.
    if (contador > 10) {
        printf("Contador é maior que 10!\n");
    } else {
        printf("Contador é menor ou igual a 10!\n");
    }

    return 0;
}
