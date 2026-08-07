#include <stdio.h>
#include <stdlib.h>
typedef struct no {
	int valor;
	int altura;
	struct no *esquerda;
	struct no *direita;
} Arv;
int altura(Arv *arv)
{
	return ((arv != NULL)? arv->altura : -1);
}
int novaAlt(Arv *esquerda, Arv *direita)
{
	int altEsq = altura(esquerda), altDir = altura(direita);
	return 1 + ((altEsq >= altDir)? altEsq : altDir);
}
Arv *iniciaArv()
{
	return NULL;
}
Arv *criaArv(Arv *esquerda, int valor, Arv *direita)
{
	Arv *arv = (Arv*) malloc(sizeof(Arv));
	int altEsq = altura(esquerda), altDir = altura(direita);
	arv->valor = valor;
	arv->altura = novaAlt(esquerda, direita);
	arv->esquerda = esquerda;
	arv->direita = direita;
	return arv;
}
Arv *criaFolha(int valor)
{
	return criaArv(NULL, valor, NULL);
}
Arv *destroiArv(Arv *arv)
{
	if (arv->esquerda != NULL) {
		arv->esquerda = destroiArv(arv->esquerda);
	} else if (arv->direita != NULL) {
		arv->direita = destroiArv(arv->direita);
	}
	free(arv);
	return NULL;
}
Arv *giraParaEsquerda(Arv *arv)
{
	Arv *Te = arv->esquerda;
	Arv *Td = arv->direita;
	Arv *Tde = Td->esquerda;
	Arv *Tdd = Td->direita;
	arv->direita = Tde;
	arv->altura = novaAlt(Te, Tde);
	Td->esquerda = arv;
	Td->altura = novaAlt(arv, Tdd);
	return Td;
}
Arv *giraParaDireita(Arv *arv)
{
	Arv *Te = arv->esquerda;
	Arv *Td = arv->direita;
	Arv *Tee = Te->esquerda;
	Arv *Ted = Te->direita;
	arv->esquerda = Ted;
	arv->altura = novaAlt(Ted, Td);
	Te->direita = arv;
	Te->altura = novaAlt(Tee, arv);
	return Te;
}
Arv *giraDireitaEsquerda(Arv *arv)
{
	arv->direita = giraParaDireita(arv->direita);
	return giraParaEsquerda(arv);
}
Arv *giraEsquerdaDireita(Arv *arv)
{
	arv->esquerda = giraParaEsquerda(arv->esquerda);
	return giraParaDireita(arv);
}
int fatorDeBalanceamento(Arv *arv)
{
	return ((arv != NULL)?
			altura(arv->esquerda) - altura(arv->direita):
			0);
}
Arv *_insereFolha(Arv *folha, Arv *arv)
{
	if (arv == NULL)
		return folha;
	int balArv, balSub;
	if (folha->valor < arv->valor) {
		arv->esquerda = _insereFolha(folha, arv->esquerda);
		arv->altura = novaAlt(arv->esquerda, arv->direita);
		balArv = fatorDeBalanceamento(arv);
		balSub = fatorDeBalanceamento(arv->esquerda);
	} else if (arv->valor < folha->valor) {
		arv->direita = _insereFolha(folha, arv->direita);
		arv->altura = novaAlt(arv->esquerda, arv->direita);
		balArv = fatorDeBalanceamento(arv);
		balSub = fatorDeBalanceamento(arv->direita);
	}
	if (balArv > 1)
		arv = ((balSub < 0)?
				giraEsquerdaDireita(arv):
				giraParaDireita(arv));
	else if (balArv < -1)
		arv = ((balSub > 0)?
				giraDireitaEsquerda(arv):
				giraParaEsquerda(arv));
	return arv;
}
Arv *insereValor(int valor, Arv *arv)
{
	Arv *folha = criaFolha(valor);
	if (arv != NULL)
		return _insereFolha(folha, arv);
	return folha;
}
void mostraArv(Arv *arv)
{
	if (arv != NULL) {
		if (arv->esquerda) {
			mostraArv(arv->esquerda);
			putchar(' ');
		}
		printf("%d", arv->valor);
		if (arv->direita) {
			putchar(' ');
			mostraArv(arv->direita);
		}
	}
}
int elementoDe(int valor, Arv *arv)
{
	return (arv != NULL) && ((arv->valor == valor) ||
			(valor < arv->valor && elementoDe(valor, arv->esquerda)) ||
			(arv->valor < valor && elementoDe(valor, arv->direita)));
}
Arv *removeValorMostra(int valor, Arv *arv)
{
	int balArv, balSub;
	if (arv == NULL) {
		return arv;
	} else if (valor < arv->valor) {
		arv->esquerda = removeValorMostra(valor, arv->esquerda);
		arv->altura = novaAlt(arv->esquerda, arv->direita);
		balArv = fatorDeBalanceamento(arv);
		balSub = fatorDeBalanceamento(arv->direita);
		if (balArv < -1)
			arv = ((balSub > 0)?
					giraDireitaEsquerda(arv):
					giraParaEsquerda(arv));
	} else if (arv->valor < valor) {
		arv->direita = removeValorMostra(valor, arv->direita);
		arv->altura = novaAlt(arv->esquerda, arv->direita);
		balArv = fatorDeBalanceamento(arv);
		balSub = fatorDeBalanceamento(arv->esquerda);
		if (balArv > 1)
			arv = ((balSub < 0)?
					giraEsquerdaDireita(arv):
					giraParaDireita(arv));
	} else {
		if (arv->direita == NULL) {
			Arv *aux = arv;
			arv = arv->esquerda;
			free(aux);
		} else if (arv->esquerda == NULL) {
			Arv *aux = arv;
			arv = arv->direita;
			free(aux);
		} else {
			Arv *pai = arv;
			Arv *filho = arv->esquerda;
			while (filho->direita != NULL) {
				pai = filho;
				filho = filho->direita;
			}
			arv->valor = filho->valor;
			filho->valor = valor;
			arv->esquerda = removeValorMostra(valor, arv->esquerda);
			arv->altura = novaAlt(arv->esquerda, arv->direita);
			balArv = fatorDeBalanceamento(arv);
			balSub = fatorDeBalanceamento(arv->direita);
			if (balArv < -1)
				arv = ((balSub > 0)?
						giraDireitaEsquerda(arv):
						giraParaEsquerda(arv));
		}
	}
	return arv;
}
Arv *leLista()
{
	int valor;
	Arv *arv = iniciaArv();
	scanf("%d%*[ ]", &valor);
	while (valor != 0) {
		arv = insereValor(valor, arv);
		scanf("%d%*[ ]", &valor);
	}
	return arv;
}
int main()
{
	Arv *arv = leLista();
	int valor;
	mostraArv(arv);
	printf("\n%d %d\n",arv->altura, arv->valor);
	scanf("%d%*[ ]", &valor);

	while (valor) {
		if (elementoDe(valor, arv)) {
			arv = removeValorMostra(valor, arv);
			mostraArv(arv);
			printf("\n%d %d\n",
					arv->altura,
					arv->valor);
		}
		scanf("%d%*[ ]", &valor);
	}
	arv = destroiArv(arv);
	return 0;
}
