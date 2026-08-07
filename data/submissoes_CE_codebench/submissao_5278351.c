#include<stdio.h>
#include<stdbool.h>
#include<stdlib.h>

typedef struct AVLtree{
    struct AVLtree *esq;
    struct AVLtree *dir;
    int    val;
    int    altura;
}AVLtree;

typedef struct tipoRegistro{
	int dado;
}tipoRegistro;

typedef struct no{
	tipoRegistro val;
	struct no *prox;
}no;

typedef struct lifo{
	struct no *prim;
    struct no *ult;
}lifo;

void criaFila(lifo *plista){
	plista->prim=NULL;
    plista->ult=NULL;
}

void inserirtree(lifo *plista,tipoRegistro *al){
	no *aux;
	aux = (no *) malloc(sizeof(no));
	aux->val = *al;
    aux->prox = NULL;
    if(plista->ult){
        plista->ult->prox =aux;
    }else{
        plista->prim = aux;
    }
    plista->ult = aux;
}


AVLtree * choose(AVLtree * no1, AVLtree * no2){
    return no1 ? no1 : no2;
}

int max(int num1 , int num2 ){
    return (num1 > num2) ? num1 : num2;
}

int alturaNo(AVLtree *raiz){
    return raiz ? raiz->altura : 0;
}

int atualizaAltura(AVLtree *raiz){
    if(raiz == NULL) return 0;
    raiz->altura =  1 + max(alturaNo(raiz->esq), alturaNo(raiz->dir));
    return raiz->altura;
}

int fatorDeBalanceamento(AVLtree *raiz){
    return raiz ? alturaNo(raiz->esq) - alturaNo(raiz->dir) : 0;
}

void libraArvoreAVL(AVLtree *raiz){
    if(raiz){
      libraArvoreAVL(raiz->esq);
      libraArvoreAVL(raiz->dir);
      free(raiz);
    }
}

AVLtree *novoNo(int val){
    AVLtree *novoAux = (struct AVLtree *) malloc(sizeof(AVLtree));
    novoAux->val    =  val;
    novoAux->altura  =  1;
    novoAux->esq    =  NULL;
    novoAux->dir = NULL;
    return novoAux;
}


AVLtree *rodaDireita(AVLtree *raiz){
    if(raiz) {
        AVLtree *raizEsq = raiz->esq;
        AVLtree *raizEsqDir = raizEsq->dir; 
		raizEsq->dir = raiz;
        raiz->esq  = raizEsqDir;
        atualizaAltura(raiz);
        atualizaAltura(raizEsq);
        return raizEsq;
    }
    return raiz;
}




AVLtree *rodaEsquerda(AVLtree*raiz){
    if(raiz) {
        AVLtree *raizDir = raiz->dir;
        AVLtree *raizDirEsq = raizDir->esq;
        raizDir->esq = raiz;
        raiz->dir = raizDirEsq;
        atualizaAltura(raiz);
        atualizaAltura(raizDir);
        return raizDir;
    }
    return raiz;
}


AVLtree *insereNo(struct AVLtree *raiz, int val){
    if(raiz){
	if(raiz->val != val){
            if(val < raiz->val) {
                raiz->esq  = insereNo(raiz->esq, val);
            } else if(val > raiz->val) {
                raiz->dir = insereNo(raiz->dir, val);
            } 
            atualizaAltura(raiz);

            int fatorBalancamento = fatorDeBalanceamento(raiz);

            if(fatorBalancamento > 1) {
                if(val > raiz->esq->val) raiz->esq  = rodaEsquerda(raiz->esq);
                raiz = rodaDireita(raiz);
            } else if (fatorBalancamento < -1) {
                if(val < raiz->dir->val) raiz->dir = rodaDireita(raiz->dir);
                raiz = rodaEsquerda(raiz);
            }
	}

	return raiz;
    }

    return novoNo(val);
}
AVLtree *deletaNo( AVLtree *raiz, int val){
    if(raiz){
        if(val < raiz->val){
            raiz->esq = deletaNo(raiz->esq, val);
        }else if(val > raiz->val){
            raiz->dir = deletaNo(raiz->dir, val);
        } else {
            if(!(raiz->esq || raiz->dir)){
                free(raiz); 
                return NULL;
            } else if(raiz->esq == NULL ^ raiz->dir == NULL){
                AVLtree * temp = choose(raiz->dir, raiz->esq);
                free(raiz);
                raiz = temp;
            } else{
                AVLtree * temp = raiz->esq;
                while(temp->dir) temp = temp->dir;
                raiz->val = temp->val;
                raiz->esq = deletaNo(raiz->esq, temp->val);
            }
        }
        atualizaAltura(raiz);
        int fatorBalancemaento = fatorDeBalanceamento(raiz);
        if(1 < fatorBalancemaento) {
             if(fatorDeBalanceamento(raiz->esq) < 0)  raiz->esq = rodaEsquerda(raiz->esq); 
             raiz = rodaDireita(raiz);
        } else if(fatorBalancemaento < -1) {
            if(fatorDeBalanceamento(raiz->dir) > 0) raiz->dir = rodaDireita(raiz->dir); 
            raiz = rodaEsquerda(raiz);
        }
    }
    return raiz;
}

int procura_no(AVLtree *no, int val) {
  if (no == NULL) {
    return 0;
  }
  if (val == no->val) {
    return 1;
  }
  if (val < no->val) {
    return procura_no(no->esq, val);
  } else {
    return procura_no(no->dir, val);
  }
}

void print_no(AVLtree *no) {
        if (no == NULL) {
            return;
        }
        print_no(no->esq);
        printf("%d ", no->val);
        print_no(no->dir);
}

void print_data(AVLtree *no) {
        if (no == NULL) {
            return;
        }
        printf("\n%d %d\n", no->altura -1 , no->val);
}

void deletaNoInseridos(AVLtree *raiz, lifo *plista){
	no *aux;
	aux = plista->prim;
    while(aux){
        if(procura_no(raiz,aux->val.dado)){
            raiz = deletaNo(raiz, aux->val.dado);
            print_no(raiz);
		      print_data(raiz);

        }
        aux = aux->prox;
    }
}


int main(){
		AVLtree *raiz = NULL;
		int dado;
		lifo deletar;
		tipoRegistro fila;
		criaFila(&deletar);
	
		while(1){
			scanf("%d", &dado);
			if(dado == 0)break;
			raiz = insereNo(raiz, dado);
		}

		while(1) {
			scanf("%d", &fila.dado);
			if(fila.dado == 0) break;
			inserirtree(&deletar, &fila);
		}
		print_no(raiz);
		print_data(raiz);
      deletaNoInseridos(raiz,&deletar);
   	return 0;
}

