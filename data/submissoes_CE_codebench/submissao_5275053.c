#include "stdio.h"
#include "stdlib.h"

typedef struct no NO;
struct no{
	
	int num;
	NO *esquerda;
	NO *direita;
	
};

NO *criarArvore(){
	
	return NULL;
}

int acha(NO **Raiz, int num){
	if(*Raiz == NULL){
		return 0;
	}else{
		if((*Raiz)->num != num){
			return acha(&(*Raiz)->direita,num) + acha(&(*Raiz)->esquerda, num);
		}else{
			return 1;
		}
	}
}

NO insercao(NO **Raiz, int num){
	
	if(*Raiz == NULL){
		
		*Raiz = (NO *)malloc(sizeof (NO));
		(*Raiz)->esquerda = NULL;
		(*Raiz)->direita = NULL;
		(*Raiz)->num = num;
	}else{
		if(acha(&(*Raiz), num)==0){
			if(num < (*Raiz)->num){
				insercao(&(*Raiz)->esquerda, num);
			}else{
				insercao(&(*Raiz)->direita, num);
			}
		}
	}
	
}



int altura(NO *Raiz){
	
	if((Raiz == NULL) || (Raiz->esquerda == NULL && Raiz->direita == NULL)){
		return 0;
	}else{
		int esq = 1 + altura(Raiz->esquerda);
		int dir = 1 + altura(Raiz->direita);
		if(esq > dir){
			return esq;
		}else{
			return dir;
		}
		
	
	}
	
	
}

int Fb(NO *no){
	
	return altura(no->esquerda) - altura(no->direita);
	
}

void rotacaoLL(NO **raiz){
	
	NO *no;
	no = (*raiz)->esquerda;
	(*raiz)->esquerda = no->direita;
	no->direita = *raiz;
	*raiz = no;
	
}

void rotacaoRR(NO **raiz){
	
	NO *no;
	no = (*raiz)->direita;
	(*raiz)->direita = no->esquerda;
	no->esquerda = (*raiz);
	*raiz = no;
	
}

void rotacaoLR(NO **raiz){
	
	rotacaoRR(&(*raiz)->esquerda);
	rotacaoLL(raiz);
	
}

void rotacaoRL(NO **raiz){
	
	rotacaoLL(&(*raiz)->direita);
	rotacaoRR(raiz);
}

void balanceamento(NO **raiz){
	
	if((*raiz)->esquerda != NULL && (*raiz)->direita != NULL){
		
		int fb = Fb(*raiz);
		int fbe = Fb((*raiz)->esquerda);
		int fbd = Fb((*raiz)->direita);
		
		if(fb >1 || fb < -1){
			if(fb>1 && fbe == 1){
				rotacaoLL(raiz);
			}else if(fb<1 && fbd == -1){
				rotacaoRR(raiz);
			}else if(fb>1 && fbe == -1){
				rotacaoLR(raiz);
			}else if(fb<1 && fbd == 1){
				rotacaoRL(raiz);
			}
		}
		
	}
	/*
	int fb = Fb(*raiz);
	if(fb >1 || fb < -1){
		printf(" salve ");
		balanceamento(raiz);
	}
	*/
}

NO *remover(NO *raiz, int num){
	
	if(raiz == NULL){
		return NULL;
	}else if(raiz->num > num){
		raiz->esquerda = remover(raiz->esquerda, num);
	}else if(raiz->num < num){
		raiz->direita = remover(raiz->direita, num);
	}else{
		if(raiz->esquerda == NULL && raiz->direita == NULL){
			free(raiz);
			raiz = NULL;
		}else if(raiz->esquerda == NULL){
			NO *aux = raiz;
			raiz = raiz->direita;
			free(aux);
		}else if(raiz->direita == NULL){
			NO *aux = raiz;
			raiz = raiz->esquerda;
			free(aux);
		}else{
			NO *pai = raiz;
			NO *aux = raiz->esquerda;
			while(aux->direita != NULL){
				pai = aux;
				aux = aux->direita;
			}
			raiz->num = aux->num;
			aux->num = num;
			raiz->esquerda = remover(raiz->esquerda, num);
		}
	}
	return raiz;
	
}

void imprimir(NO *raiz){
	
	if(raiz != NULL){
		imprimir(raiz->esquerda);
		printf("%d ", raiz->num);
		imprimir(raiz->direita);
	}
	
}

int main(){
	
	NO *raiz = criarArvore();
	int num;
	scanf("%d", &num);
	
	while(num != 0){
		insercao(&raiz, num);
		balanceamento(&raiz);
		scanf("%d", &num);
	}
	
	imprimir(raiz);
	printf("\n");
	int aux = altura(raiz);
	printf("%d ", num);
	printf("%d \n", raiz->num);
	
	scanf("%d", &num);
	while(num!= 0){
		remover(raiz, num);
		balanceamento(&raiz);
		
		imprimir(raiz);
		printf("\n");
		aux = altura(raiz);
		printf("%d ", num);
		printf("%d \n", raiz->num);
		
		scanf("%d", &num);
	}
	
}

