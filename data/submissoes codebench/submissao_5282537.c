#include<stdio.h>
#include<stdlib.h>

int contaNos = 0;

struct No{
	int chave;
	struct No *esquerda;
	struct No *direita;
	int altura;
};

int maximo(int a, int b);

int altura(struct No *N){
	if (N == NULL)
		return 0;
	return N->altura;
}

int maximo(int a, int b){
	return (a > b)? a : b;
}

struct No* novoNo(int chave){
	struct No* No = (struct No*)
						malloc(sizeof(struct No));
	No->chave = chave;
	No->esquerda = NULL;
	No->direita = NULL;
	No->altura = 1;
	return(No);
}

struct No *direitaRotacao(struct No *y){
	struct No *x = y->esquerda;
	struct No *T2 = x->direita;

	x->direita = y;
	y->esquerda = T2;

	y->altura = maximo(altura(y->esquerda), altura(y->direita))+1;
	x->altura = maximo(altura(x->esquerda), altura(x->direita))+1;

	return x;
}

struct No *esquerdaRotacao(struct No *x)
{
	struct No *y = x->direita;
	struct No *T2 = y->esquerda;

	y->esquerda = x;
	x->direita = T2;

	x->altura = maximo(altura(x->esquerda), altura(x->direita))+1;
	y->altura = maximo(altura(y->esquerda), altura(y->direita))+1;

	return y;
}

int obterBalanceamento(struct No *N){
	if (N == NULL){
		return 0;
    }

	return altura(N->esquerda) - altura(N->direita);
}

struct No* insere(struct No* No, int chave){
	if (No == NULL)
		return(novoNo(chave));

	if (chave < No->chave)
		No->esquerda = insere(No->esquerda, chave);
	else if (chave > No->chave)
		No->direita = insere(No->direita, chave);
	else 
		return No;

	No->altura = 1 + maximo(altura(No->esquerda),
						altura(No->direita));

	int balance = obterBalanceamento(No);

	if (balance > 1 && chave < No->esquerda->chave)
		return direitaRotacao(No);

	if (balance < -1 && chave > No->direita->chave)
		return esquerdaRotacao(No);

	if (balance > 1 && chave > No->esquerda->chave)
	{
		No->esquerda = esquerdaRotacao(No->esquerda);
		return direitaRotacao(No);
	}
    
	if (balance < -1 && chave < No->direita->chave)
	{
		No->direita = direitaRotacao(No->direita);
		return esquerdaRotacao(No);
	}

	return No;
}


struct No * minimoValorNo(struct No* No){
	struct No* atual = No;

	while (atual->esquerda != NULL)
		atual = atual->esquerda;

	return atual;
}

struct No* deletaNo(struct No* raiz, int chave){

	if (raiz == NULL)
		return raiz;

	if ( chave < raiz->chave )
		raiz->esquerda = deletaNo(raiz->esquerda, chave);

	else if( chave > raiz->chave )
		raiz->direita = deletaNo(raiz->direita, chave);

	else
	{
		// No com um filho ou sem filho
		if( (raiz->esquerda == NULL) || (raiz->direita == NULL) )
		{
			struct No *temp = raiz->esquerda ? raiz->esquerda :
											raiz->direita;

			// Não é filho
			if (temp == NULL)
			{
				temp = raiz;
				raiz = NULL;
			}
			else
			*raiz = *temp; 

			free(temp);
		}
		else
		{
			struct No* temp = minimoValorNo(raiz->direita);

			raiz->chave = temp->chave;

			raiz->direita = deletaNo(raiz->direita, temp->chave);
		}
	}

	if (raiz == NULL)
	return raiz;

	raiz->altura = 1 + maximo(altura(raiz->esquerda),
						altura(raiz->direita));

	int balance = obterBalanceamento(raiz);

	if (balance > 1 && obterBalanceamento(raiz->esquerda) >= 0)
		return direitaRotacao(raiz);

	if (balance > 1 && obterBalanceamento(raiz->esquerda) < 0)
	{
		raiz->esquerda = esquerdaRotacao(raiz->esquerda);
		return direitaRotacao(raiz);
	}

	if (balance < -1 && obterBalanceamento(raiz->direita) <= 0)
		return esquerdaRotacao(raiz);

	if (balance < -1 && obterBalanceamento(raiz->direita) > 0)
	{
		raiz->direita = direitaRotacao(raiz->direita);
		return esquerdaRotacao(raiz);
	}

	return raiz;
}


struct No * minimoValorNoAux(struct No* No){
	struct No* atual = No;

	while (atual->direita != NULL)
		atual = atual->direita;

	return atual;
}

struct No* deletaNoAux(struct No* raiz, int chave){

	if (raiz == NULL)
		return raiz;

	if ( chave < raiz->chave )
		raiz->esquerda = deletaNo(raiz->esquerda, chave);

	else if( chave > raiz->chave )
		raiz->direita = deletaNo(raiz->direita, chave);

	else
	{
		// No com um filho ou sem filho
		if( (raiz->esquerda == NULL) || (raiz->direita == NULL) )
		{
			struct No *temp = raiz->esquerda ? raiz->esquerda :
											raiz->direita;

			// Não é filho
			if (temp == NULL)
			{
				temp = raiz;
				raiz = NULL;
			}
			else
			*raiz = *temp; 

			free(temp);
		}
		else
		{
			struct No* temp = minimoValorNoAux(raiz->esquerda);

			raiz->chave = temp->chave;

			raiz->esquerda = deletaNo(raiz->esquerda, temp->chave);
		}
	}

	if (raiz == NULL)
	return raiz;

	raiz->altura = 1 + maximo(altura(raiz->esquerda),
						altura(raiz->direita));

	int balance = obterBalanceamento(raiz);

	if (balance > 1 && obterBalanceamento(raiz->esquerda) >= 0)
		return direitaRotacao(raiz);

	if (balance > 1 && obterBalanceamento(raiz->esquerda) < 0)
	{
		raiz->esquerda = esquerdaRotacao(raiz->esquerda);
		return direitaRotacao(raiz);
	}

	if (balance < -1 && obterBalanceamento(raiz->direita) <= 0)
		return esquerdaRotacao(raiz);

	if (balance < -1 && obterBalanceamento(raiz->direita) > 0)
	{
		raiz->direita = direitaRotacao(raiz->direita);
		return esquerdaRotacao(raiz);
	}

	return raiz;
}

void imprimeInfixada(struct No *raiz){
	if(raiz != NULL)
	{
		imprimeInfixada(raiz->esquerda);
		printf("%d ", raiz->chave);
		imprimeInfixada(raiz->direita);
	}
}

int contaNosFunc(struct No *raiz){

	if(raiz != NULL)
	{
		contaNosFunc(raiz->esquerda);
		contaNos++;
		contaNosFunc(raiz->direita);
	}
	return contaNos;
}


int main()
{
    //struct No *raiz = NULL;
	struct No *aux = NULL;

    int numero, deleta, totalDeNos;

    // 3 2 1 4 5 6 7 16 15 14 0
    while(scanf("%d", &numero), numero != 0){
        //raiz = insere(raiz, numero);
		aux = insere(aux, numero);
    }
	//imprimeInfixada(raiz);
	imprimeInfixada(aux);
    // printf("\n%d ", raiz->altura - 1);
    printf("\n%d ", maximo(altura(aux->esquerda),
						altura(aux->direita)));
    printf("%d", aux->chave);
    printf("\n");
	// totalDeNos = contaNosFunc(raiz);
	totalDeNos = contaNosFunc(aux);
	contaNos = 0;

    // 4 10 7 0
    while(scanf("%d", &deleta), deleta != 0){
        // raiz = deletaNo(raiz, deleta);
		aux = deletaNoAux(aux, deleta);
		contaNos = 0;

		if(totalDeNos - 1 == contaNosFunc(aux)){
			// imprimeInfixada(raiz);
			imprimeInfixada(aux);
			// printf("\n%d ", raiz->altura - 1);
			printf("\n%d ", maximo(altura(aux->esquerda),
						altura(aux->direita)));
			printf("%d", aux->chave);
			printf("\n");
			totalDeNos--;
			contaNos = 0;
		};
    }

	return 0;
}
