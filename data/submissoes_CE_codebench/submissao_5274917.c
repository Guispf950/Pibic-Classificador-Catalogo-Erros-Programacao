//arvore AVL - aed2

#include <stdio.h>
#include <stdlib.h>

typedef struct tipoNo {
    int valor;
    struct tipoNo *esq, *dir;
} tipoNo;

tipoNo* cria(int valor) {
    tipoNo *aux;
    aux = (tipoNo*) malloc(sizeof(tipoNo));
    aux->valor = valor;
    aux->esq = NULL; aux->dir = NULL;
    return aux;
}

int altura (tipoNo *raiz) {
    if(raiz == NULL) {
        return -1;
    }
    if(altura(raiz->esq) > altura(raiz->dir)) {
        return altura(raiz->esq) +1;
    }
    return altura(raiz->dir) +1;
}

//fator de balanceamento
int fb(tipoNo *raiz) {
    if(raiz != NULL) {
        return(altura(raiz->esq) - altura(raiz->dir));
    }
    return 0;
}

tipoNo* rotacionaDir (tipoNo *no) {
    tipoNo *aux = no->esq;
    no->esq = aux->dir;
    aux->dir = no;
    return aux;
}

tipoNo* rotacionaEsq (tipoNo *no) {
    tipoNo *aux = no->dir;
    no->dir = aux->esq;
    aux->esq = no;
    return aux;
}

tipoNo* balanceamento(tipoNo *raiz, int valor) {
    int FB = fb(raiz);

    if(FB > 1 && valor <= raiz->esq->valor) {
        return rotacionaDir(raiz);
    }
    if(FB < -1 && valor > raiz->dir->valor) {
        return rotacionaEsq(raiz);
    }
    if(FB > 1 && valor > raiz->esq->valor) {
        raiz->esq = rotacionaEsq(raiz->esq);
        return rotacionaDir(raiz);
    }
    if(FB < -1 && valor <= raiz->dir->valor) {
        raiz->dir = rotacionaDir(raiz->dir);
        return rotacionaEsq(raiz);
    }
    
}

tipoNo* insereNaArv(tipoNo *raiz, int valor) {

    if(raiz == NULL) {
        raiz = cria(valor);
    }
    else if(valor <= raiz->valor) {
        raiz->esq = insereNaArv(raiz->esq, valor);
    } else if(valor > raiz->valor) {
        raiz->dir = insereNaArv(raiz->dir, valor);
    }

    int FB = fb(raiz);

    if(FB > 1 && valor <= raiz->esq->valor) {
        return rotacionaDir(raiz);
    }
    if(FB < -1 && valor > raiz->dir->valor) {
        return rotacionaEsq(raiz);
    }
    if(FB > 1 && valor > raiz->esq->valor) {
        raiz->esq = rotacionaEsq(raiz->esq);
        return rotacionaDir(raiz);
    }
    if(FB < -1 && valor <= raiz->dir->valor) {
        raiz->dir = rotacionaDir(raiz->dir);
        return rotacionaEsq(raiz);
    }
    return raiz;
}

int buscaValor(tipoNo *raiz, int x) {
    if(raiz == NULL) {
        return 0;
    } else if(raiz->valor == x) {
        return 1;
    } else if(x <= raiz->valor) {
        return buscaValor(raiz->esq, x);
    } else if (x > raiz->valor) {
        return buscaValor(raiz->dir, x);
    }
}

tipoNo* deleta(tipoNo *raiz, int valor) {
    if(raiz == NULL) {
        return NULL;
    } else if(valor < raiz->valor) {
        raiz->esq = deleta(raiz->esq, valor);
    } else if(valor > raiz->valor) {
        raiz->dir = deleta(raiz->dir, valor);
    } else { //achou o nó
        //nó sem filhos
        if(raiz->esq == NULL && raiz->dir == NULL) {


            free(raiz);
            raiz = NULL;
        }
        //nó só tem filho à direita
        else if(raiz->esq == NULL) {
            tipoNo *aux = raiz;
            raiz = raiz->dir;
            free(aux);
        }
        //só tem filho à esquerda
        else if(raiz->dir == NULL) {
            tipoNo *aux = raiz;
            raiz = raiz->esq;
            free(aux);
        }
        //nó tem os dois filhos
        else {
            tipoNo *temp = raiz->esq;
            while(temp->dir != NULL) {
                temp = temp->dir;
            }
            raiz->valor = temp->valor;
            temp->valor = valor;
            raiz->esq = deleta(raiz->esq, valor);
        }
    }

    balanceamento(raiz, valor);

    return raiz;
}

void infixa (tipoNo *raiz) {
    if(raiz == NULL) {
        return;
    }
    infixa (raiz->esq);
    printf("%d ", raiz->valor);
    infixa (raiz->dir);
}

void libera (tipoNo *raiz) {
    if(raiz == NULL) {
        return;
    }
    libera(raiz->esq);
    libera(raiz->dir);
    free(raiz);
}

int main () {
    tipoNo *raiz, *raizNova;
    raiz = NULL;

    int valor;
    scanf("%d%*c", &valor);
    while(valor != 0) {
        raiz = insereNaArv(raiz, valor);
        scanf("%d%*c", &valor);
    }
    infixa(raiz);
    printf("\n");
    printf("%d %d\n", altura(raiz), raiz->valor);

    scanf("%d%*c", &valor);
    while(valor != 0) {

        if(buscaValor(raiz, valor) == 1) {
            raiz = deleta(raiz, valor);
            infixa(raiz); printf("\n");
            printf("%d %d\n", altura(raiz), raiz->valor);
        }
        scanf("%d%*c", &valor);
    }
    libera(raiz);
}
