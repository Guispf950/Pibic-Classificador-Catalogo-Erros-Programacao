#include <stdio.h>
#include <stdlib.h>

typedef struct ArVL {
	int n;
	struct ArVL *esq;
	struct ArVL *dir;
}ArVL;

ArVL* criaNo(int i) {
	ArVL* aux = (ArVL*) malloc(sizeof(ArVL));
	aux->n = i;
	aux->esq = NULL;
	aux->dir = NULL;
	
	return aux;
}

ArVL* rotEsq (ArVL* p) {
	ArVL *aux = p->dir;
	p->dir = aux->esq;
	aux->esq = p;
	
	return aux;
}

ArVL* rotDir (ArVL* p) {
	ArVL *aux = p->esq;
	p->esq = aux->dir;
	aux->dir = p;
	
	return aux;
}


int removeNo (int i, ArVL* raiz) {
	if(raiz->esq == NULL && raiz->dir == NULL) {
		return 0;
	}
	if(raiz->dir->n == i) {
		ArVL *tmp = raiz->dir;
		raiz->dir = tmp->dir;
		free(tmp);
		return 1;
	}
	if(raiz->esq->n == i) {
		ArVL *tmp = raiz->esq;
		raiz->esq = tmp->esq;
		free(tmp);
		return 1;
	}
	else {
		removeNo(i,raiz->esq);
		removeNo(i,raiz->dir);
	}
}



int altura (ArVL* raiz)
{
  if(raiz==NULL)
  {
    return 0;
  }
  else
  {
    if(altura(raiz->esq) > altura(raiz->dir))
      return altura(raiz->esq) + 1;
    else
      return altura(raiz->dir) + 1;
  }
}

int busca(ArVL* no, int i) {
	if(no->dir = no->esq = NULL) {
		return 0;
	}
	if(no->dir) {
		if(no->dir-> n == i) {
			return 1;
		}
		else busca(no,i);
	}
	if(no->esq) {
		if(no->esq->n == i) {
			return 1;
		}
		else busca(no,i);
	}
}
int FB (ArVL* no) {
	if(no != NULL) {
		return(altura(no->esq)- altura(no->dir));
	}
	else {
		return 0;
	}
}

ArVL* insere (ArVL* raiz, int i) {
	if(raiz==NULL) {
		raiz = criaNo(i);
		return raiz;
	}
	else if(i < raiz->n) {
		raiz->esq = insere(raiz->esq,i);
	}
	else if(i > raiz->n) {
		raiz->dir = insere(raiz->dir,i);
	}
	int fator = FB(raiz);
	//rotações simples
	if(fator < -1  && i > raiz->dir->n) {
		return rotEsq(raiz);
	}
	if(fator > 1 && i < raiz->esq->n) {
		return rotDir(raiz);
	}
	//rotações duplas 
	if(fator < -1 && i < raiz->dir->n) {
		raiz->dir = rotDir(raiz->dir);
		return rotEsq(raiz);
	}
	if(fator > 1 && i > raiz->esq->n) {
		raiz->esq = rotEsq(raiz->esq);
		return rotDir(raiz);
	}
	//fator == -1, 0 ou 1.
	return raiz;
}

//edit1( alias E1) implementar as funções ROTAÇAO simples e dupla; ok
//Ir rotacionando conforme INSERE se necessário; ok
//Dar um jeito de sempre VERIFICAR a altura, associada a necessidade de rotação; ok 
//implementar a função RETIRA da árvore. ok
//implementar a função busca;
//implementar a funcao IMPRIME;

int main () {
	//solucao pensada na madrugada pra colocar dps:
	int a;
	ArVL Arvore;
	scanf("%d",&a);
	while(a != 0) {
		insere(&Arvore,a);
		scanf("%d",&a);
	}
	//imprime(&Arvore);
	printf("%d ",altura(&Arvore));
	printf("%d\n", Arvore.n);
	scanf("%d",&a);
	while(a != 0) {
		if(removeNo(a,&Arvore)) {
			//imprime(&Arvore);
		}
		scanf("%d",&a);
	}

}