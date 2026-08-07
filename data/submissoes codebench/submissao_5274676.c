#include<stdio.h>
#include<stdbool.h>
#include<stdlib.h>

typedef struct arvoreAVL{
    struct arvoreAVL *esq;
    struct arvoreAVL *dir;
    int    dado;
    int    altura;
}arvoreAVL;

typedef struct tipoRegistro{
	int num;
}tipoRegistro;

typedef struct tipoNo{
	tipoRegistro dado;
	struct tipoNo *prox;
}tipoNo;

typedef struct tipoFila{
	struct tipoNo *prim;
    struct tipoNo *ult;
}tipoFila;

void criaFila(tipoFila *plista){
	plista->prim=NULL;
    plista->ult=NULL;
}

void inserirNafila(tipoFila *plista,tipoRegistro *al){
	tipoNo *aux;
	aux = (tipoNo *) malloc(sizeof(tipoNo));
	aux->dado = *al;
    aux->prox = NULL;
    if(plista->ult){
        plista->ult->prox =aux;
    }else{
        plista->prim = aux;
    }
    plista->ult = aux;
}


arvoreAVL * choose(arvoreAVL * no1, arvoreAVL * no2){
    return no1 ? no1 : no2;
}

int max(int num1 , int num2 ){
    return (num1 > num2) ? num1 : num2;
}

int alturaDoNo(arvoreAVL *raiz){
    return raiz ? raiz->altura : 0;
}

int atualizaAltura(arvoreAVL *raiz){
    if(raiz == NULL) return 0;
    raiz->altura =  1 + max(alturaDoNo(raiz->esq), alturaDoNo(raiz->dir));
    return raiz->altura;
}

int fatorDeBalanceamento(arvoreAVL *raiz){
    return raiz ? alturaDoNo(raiz->esq) - alturaDoNo(raiz->dir) : 0;
}

void libraArvoreAVL(arvoreAVL *raiz){
    if(raiz){
      libraArvoreAVL(raiz->esq);
      libraArvoreAVL(raiz->dir);
      free(raiz);
    }
}

arvoreAVL *novoNo(int dado){
    arvoreAVL *novoAux = (struct arvoreAVL *) malloc(sizeof(arvoreAVL));
    novoAux->dado    =  dado;
    novoAux->altura  =  1;
    novoAux->esq    =  NULL;
    novoAux->dir = NULL;
    return novoAux;
}


arvoreAVL *rodaDireita(arvoreAVL *raiz){
    if(raiz) {
        arvoreAVL *raizEsq = raiz->esq;
        arvoreAVL *raizEsqDir = raizEsq->dir; 
		raizEsq->dir = raiz;
        raiz->esq  = raizEsqDir;
        atualizaAltura(raiz);
        atualizaAltura(raizEsq);
        return raizEsq;
    }
    return raiz;
}




arvoreAVL *rodaEsquerda(arvoreAVL *raiz){
    if(raiz) {
        arvoreAVL *raizDir = raiz->dir;
        arvoreAVL *raizDirEsq = raizDir->esq;
        raizDir->esq = raiz;
        raiz->dir = raizDirEsq;
        atualizaAltura(raiz);
        atualizaAltura(raizDir);
        return raizDir;
    }
    return raiz;
}


arvoreAVL *insereNo(struct arvoreAVL *raiz, int dado){
    if(raiz){
	if(raiz->dado != dado){
            if(dado < raiz->dado) {
                raiz->esq  = insereNo(raiz->esq, dado);
            } else if(dado > raiz->dado) {
                raiz->dir = insereNo(raiz->dir, dado);
            } 
            atualizaAltura(raiz);

            int fatorBalancamento = fatorDeBalanceamento(raiz);

            if(fatorBalancamento > 1) {
                if(dado > raiz->esq->dado) raiz->esq  = rodaEsquerda(raiz->esq);
                raiz = rodaDireita(raiz);
            } else if (fatorBalancamento < -1) {
                if(dado < raiz->dir->dado) raiz->dir = rodaDireita(raiz->dir);
                raiz = rodaEsquerda(raiz);
            }
	}

	return raiz;
    }

    return novoNo(dado);
}
arvoreAVL *deletaNo( arvoreAVL *raiz, int dado){
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
                arvoreAVL * temp = choose(raiz->dir, raiz->esq);
                free(raiz);
                raiz = temp;
            } else{
                arvoreAVL * temp = raiz->esq;
                while(temp->dir) temp = temp->dir;
                raiz->dado = temp->dado;
                raiz->esq = deletaNo(raiz->esq, temp->dado);
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

int procura_no(arvoreAVL *no, int dado) {
  if (no == NULL) {
    return 0;
  }
  if (dado == no->dado) {
    return 1;
  }
  if (dado < no->dado) {
    return procura_no(no->esq, dado);
  } else {
    return procura_no(no->dir, dado);
  }
}

void print_no(arvoreAVL *no) {
        if (no == NULL) {
            return;
        }
        print_no(no->esq);
        printf("%d ", no->dado);
        print_no(no->dir);
}

void print_data(arvoreAVL *no) {
        if (no == NULL) {
            return;
        }
        printf("\n%d %d\n", no->altura -1 , no->dado);
}

void deletaNoInseridos(arvoreAVL *raiz,tipoFila *plista){
	tipoNo *aux;
	aux = plista->prim;
    while(aux){
        if(procura_no(raiz,aux->dado.num)){
            raiz = deletaNo(raiz, aux->dado.num);
            print_no(raiz);
		      print_data(raiz);

        }
        aux = aux->prox;
    }
}


int main(){
		arvoreAVL *raiz = NULL;
		int num;
		tipoFila deletar;
		tipoRegistro fila;
		criaFila(&deletar);
	
		while(1){
			scanf("%d", &num);
			if(num == 0)break;
			raiz = insereNo(raiz, num);
		}

		while(1) {
			scanf("%d", &fila.num);
			if(fila.num == 0) break;
			inserirNafila(&deletar, &fila);
		}
		print_no(raiz);
		print_data(raiz);
      deletaNoInseridos(raiz,&deletar);
   	return 0;
}