#include<stdio.h>
#include<stdbool.h>
#include<stdlib.h>

typedef struct AVL{
	struct AVL *esq;
	struct AVL *dir;
	int    dado;
	int    altura;
}AVL;

typedef struct reg{
	int num;
}reg;

typedef struct no{
	reg dado;
	struct no *prox;
}no;

typedef struct fila{
	struct no *prim;
	struct no *ult;
}fila;

AVL * escolherNo(AVL * no_one, AVL * no_two);
AVL *novoNo(int dado);
AVL *rotacionaDireita(AVL *raiz);
AVL *rotacionaEsquerda(AVL *raiz);
AVL *insereNo(struct AVL *raiz, int dado);
AVL *deletaNo( AVL *raiz, int dado);

void criaFila(fila *plista);
void inserirNafila(fila *plista, reg *al);
int alturaNo(AVL *raiz);
int atualizaAltura(AVL *raiz);
int fatBalanceamento(AVL *raiz);
void liberaArvore(AVL *raiz);
int procuraNo(AVL *no, int dado);
void imprimeNo(AVL *no);
void imprimeDado(AVL *no);
void removeNo(AVL *raiz, fila *plista);


int main(){
		AVL *raiz = NULL;
		int n;
		fila deletar;
		reg filaNo;
		criaFila(&deletar);
		while(1){
			scanf("%d", &n);
			if(n == 0)break;
			raiz = insereNo(raiz, n);
		}
		while(1) {
			scanf("%d", &filaNo.num);
			if(filaNo.num == 0) break;
			inserirNafila(&deletar, &filaNo);
		}
		imprimeNo(raiz);
		imprimeDado(raiz);
		removeNo(raiz,&deletar);
   	return 0;
}

void criaFila(fila *plista){
	plista->prim=NULL;
	plista->ult=NULL;
}

void inserirNafila(fila *plista, reg *al){
	no *aux;
	aux = (no *) malloc(sizeof(no));
	aux->dado = *al;
	aux->prox = NULL;
	if(plista->ult)
		plista->ult->prox =aux;
	else
		plista->prim = aux;
	plista->ult = aux;
}


AVL * escolherNo(AVL * no_one, AVL * no_two){
	return no_one ? no_one : no_two;
}

int maximo(int n1 , int n2 ){
	return (n1 > n2) ? n1 : n2;
}

int alturaNo(AVL *raiz){
	return raiz ? raiz->altura : 0;
}

int atualizaAltura(AVL *raiz){
	if(raiz == NULL){
		return 0;
	}
	raiz->altura =  1 + maximo(alturaNo(raiz->esq), alturaNo(raiz->dir));
	return raiz->altura;
}

int fatBalanceamento(AVL *raiz){
	return raiz ? alturaNo(raiz->esq) - alturaNo(raiz->dir) : 0;
}

void liberaArvore(AVL *raiz){
	if(raiz)
		liberaArvore(raiz->esq);
		liberaArvore(raiz->dir);
		free(raiz);
}

AVL *novoNo(int dado){
	AVL *novoAux = (struct AVL *) malloc(sizeof(AVL));
	novoAux->dado = dado;
	novoAux->altura = 1;
	novoAux->esq = NULL;
	novoAux->dir = NULL;
	return novoAux;
}

AVL *rotacionaDireita(AVL *raiz){
	if(raiz) {
		AVL *raizEsq = raiz->esq;
		AVL *raizEsqDir = raizEsq->dir; 
		raizEsq->dir = raiz;
		raiz->esq  = raizEsqDir;
		atualizaAltura(raiz);
		atualizaAltura(raizEsq);
		return raizEsq;
	}
	return raiz;
}

AVL *rotacionaEsquerda(AVL *raiz){
	if(raiz){
		AVL *raizDir = raiz->dir;
		AVL *raizDirEsq = raizDir->esq;
		raizDir->esq = raiz;
		raiz->dir = raizDirEsq;
		atualizaAltura(raiz);
		atualizaAltura(raizDir);
		return raizDir;
	}
	return raiz;
}

AVL *insereNo(struct AVL *raiz, int dado){
	if(raiz){
	if(raiz->dado != dado){
		if(dado < raiz->dado) {
			raiz->esq  = insereNo(raiz->esq, dado);
		} else if(dado > raiz->dado) {
			raiz->dir = insereNo(raiz->dir, dado);
		} 
		atualizaAltura(raiz);
		int fatorBalancamento = fatBalanceamento(raiz);
		if(fatorBalancamento > 1) {
			if(dado > raiz->esq->dado) raiz->esq  = rotacionaEsquerda(raiz->esq);
			raiz = rotacionaDireita(raiz);
		} else if (fatorBalancamento < -1) {
			if(dado < raiz->dir->dado) raiz->dir = rotacionaDireita(raiz->dir);
			raiz = rotacionaEsquerda(raiz);
		}
	}
	return raiz;
	}
	return novoNo(dado);
}
AVL *deletaNo( AVL *raiz, int dado){
	if(raiz){
		if(dado < raiz->dado){
			raiz->esq = deletaNo(raiz->esq, dado);
		}else if(dado > raiz->dado){
			raiz->dir = deletaNo(raiz->dir, dado);
		} else {
			if(!(raiz->esq || raiz->dir)){
				free(raiz); 
				return NULL;
			} else if(raiz->esq == NULL ^ raiz->dir == NULL){
				AVL * temp = escolherNo(raiz->dir, raiz->esq);
				free(raiz);
				raiz = temp;
			} else{
				AVL * temp = raiz->esq;
				while(temp->dir) temp = temp->dir;
				raiz->dado = temp->dado;
				raiz->esq = deletaNo(raiz->esq, temp->dado);
			}
		}
		atualizaAltura(raiz);
		int fatorBalanceamento = fatBalanceamento(raiz);
		if(1 < fatorBalanceamento) {
			if(fatBalanceamento(raiz->esq) < 0)  raiz->esq = rotacionaEsquerda(raiz->esq); 
			raiz = rotacionaDireita(raiz);
		} else if(fatorBalanceamento < -1) {
			if(fatBalanceamento(raiz->dir) > 0) raiz->dir = rotacionaDireita(raiz->dir); 
			raiz = rotacionaEsquerda(raiz);
		}
	}
	return raiz;
}

int procuraNo(AVL *no, int dado) {
	if (no == NULL)
		return 0;
	if (dado == no->dado)
		return 1;
	if (dado < no->dado) 
		return procuraNo(no->esq, dado);
	else 
		return procuraNo(no->dir, dado);
}

void imprimeNo(AVL *no) {
	if (no == NULL)
		return;
	imprimeNo(no->esq);
	printf("%d ", no->dado);
	imprimeNo(no->dir);
}

void imprimeDado(AVL *no) {
	if (no == NULL) 
		return;        
	printf("\n%d %d\n", no->altura -1 , no->dado);
}

void removeNo(AVL *raiz, fila *plista){
	no *aux;
	aux = plista->prim;
	while(aux){
		if(procuraNo(raiz,aux->dado.num)){
			raiz = deletaNo(raiz, aux->dado.num);
			imprimeNo(raiz);
			imprimeDado(raiz);
		}
		aux = aux->prox;
	}
}