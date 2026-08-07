#include <stdio.h>

/*
 * Exercício CodeBench: ler uma matriz M de ordem 6x5, ler um vetor de tamanho 6,
 * e calcular o produto escalar do vetor pelas COLUNAS da matriz (resultado 1x5).
 * Entrada (formato do caso de teste cadastrado):
 *   linha 1: 30 inteiros (a matriz 6x5, em ordem de linha)
 *   linha 2: 6 inteiros (o vetor)
 * Saída: [r0 r1 r2 r3 r4]
 */
int main(void)
{
	int m[6][5];
	int vet[6];
	int res[5];

	/* lê a matriz 6x5 (30 valores, linha a linha) */
	for (int i = 0; i < 6; i++)
		for (int j = 0; j < 5; j++)
			scanf("%d", &m[i][j]);

	/* lê o vetor de tamanho 6 */
	for (int i = 0; i < 6; i++)
		scanf("%d", &vet[i]);

	/* res[j] = soma_i ( m[i][j] * vet[i] ) */
	for (int j = 0; j < 5; j++) {
		res[j] = 0;
		for (int i = 0; i < 6; i++)
			res[j] += m[i][j] * vet[i];
	}

	printf("[");
	for (int j = 0; j < 5; j++)
		printf("%d%s", res[j], (j < 4) ? " " : "");
	printf("]\n");

	return 0;
}
