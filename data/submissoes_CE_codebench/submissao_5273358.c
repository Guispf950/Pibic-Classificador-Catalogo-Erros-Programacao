#include<stdio.h>
#include<stdlib.h>
#include<string.h>


typedef struct tipoAvr{
    int valor;
    int fb;
    struct tipoAvr *dir;
    struct tipoAvr *esq;
} tipoArv;



void imprimi(tipoArv *a){
    
    if(a != NULL){
        imprimi(a->esq);
        printf("valor: %d fator: %d\n", a->valor, a->fb);
        imprimi(a->dir);
    }

}

tipoArv *iniciaArv(){
    tipoArv *novoNo = (tipoArv*)malloc(sizeof(tipoArv));
    novoNo =  NULL;
    return novoNo;

}

tipoArv *criaNovo(int numero){
    tipoArv *novoNo = (tipoArv*)malloc(sizeof(tipoArv));
    novoNo->dir = NULL;
    novoNo->esq = NULL;
    novoNo->valor = numero;

    return novoNo;

}
int altura(tipoArv *raiz){
	int he;
	int hd;
	if(raiz == NULL){
		return 0;
	}else{
		printf("\nhe: %d\n", he);
		he = 1 + altura(raiz->esq);
		return he;
		hd = 1 + altura(raiz->dir);
		return hd;
	}
	if(he > hd){
		return he;
	}else{
		return hd;
	}
}
void fator(tipoArv *arv){

	if(arv != NULL){
		fator(arv->esq);
		arv->fb = altura(arv->dir) - altura(arv->esq);
		fator(arv->dir);
	}
}
void inseri(tipoArv **arv, tipoArv *novoNo){
    tipoArv *camArv = *arv;

    if( *arv == NULL ){
        *arv = novoNo;
        fator(*arv);
    }else{
        if( novoNo->valor < camArv->valor){
            inseri(&camArv->esq, novoNo);
        }else if( novoNo->valor > camArv->valor ){
            inseri(&camArv->dir, novoNo);
        }
    }
}

void excluiNo(tipoArv *no){
    free(no);
}

void excluiSubArvore(tipoArv *a){
    

    if(a != NULL){
        excluiSubArvore(a->esq);
        excluiSubArvore(a->dir);
        excluiNo(a);
    }

}

int main(){
    int numero;
    int chave;
    
    tipoArv *a = iniciaArv();

    scanf("%d", &numero);
    while(numero != 0){
        tipoArv *novoNo = criaNovo(numero);
        inseri(&a, novoNo);
        scanf("%d", &numero);
    }

    scanf("%d", &chave);
    

    printf("\n");
    imprimi(a);

    return 0;
}