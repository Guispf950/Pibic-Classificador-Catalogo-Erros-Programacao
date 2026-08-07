#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct avl TAVL;
struct avl{
	int chave;
	TAVL* esq;
	TAVL* dir;
};
TAVL* criar_no(int valor)
{
	TAVL* no = (TAVL*) malloc(sizeof(TAVL));
	no->chave = valor;
	no->esq = NULL;
	no->dir = NULL;
	return no;
}

int altura(TAVL* root){
	if(root==NULL){
		return 0;
	}else{
		if(altura(root->esq) > altura(root->dir)){
			return altura(root->esq) + 1;
		}else{
			return altura(root->dir) + 1;
		}
  }
}

int get_fb(TAVL* no_arvore){
	if(no_arvore != NULL){
		return (altura(no_arvore->esq) - altura(no_arvore->dir));
	}
}
TAVL* rot_esq(TAVL* ponto){
	TAVL *Aux = ponto->dir;
	ponto->dir = Aux->esq;
	Aux->esq = ponto;
	return Aux;
}
TAVL* rot_dir(TAVL* ponto){
	TAVL* Aux = ponto->esq;
	ponto->esq = Aux->dir;
	Aux->dir = ponto;
	return Aux;
}
void rotacaoLL(TAVL *root){
	TAVL *no;
	no=root->esq;
	root->esq=no->dir;
	no->dir=root;
	root=no;
}
void rotacaoRR(TAVL *root){
	TAVL *no;
	no=root->dir;
	root->dir=no->esq;
	no->esq=root;
	root=no;
}
void rotacaoLR(TAVL *root){
	rotacaoRR(root->esq);
	rotacaoLL(root);
}
void rotacaoRL(TAVL *root){
	rotacaoLL(root->dir);
	rotacaoRR(root);
}

TAVL* inserir (TAVL* root, int chave){
	if(root == NULL){
		root = criar_no(chave);
		return root;
	}else if(chave < root->chave ){
		root->esq = inserir(root->esq,chave);
	}else if(chave > root->chave){
		root->dir = inserir(root->dir,chave);
	}
	int fb = get_fb(root);
	if (fb > 1 && chave < root->esq->chave){
		return rot_dir(root);
	}
	if (fb < -1 && chave > root->dir->chave){
		return rot_esq(root);
	}
	if (fb > 1 && chave > root->esq->chave){
		root->esq =  rot_esq(root->esq);
		return rot_dir(root);
	}if (fb < -1 && chave < root->dir->chave){
		root->dir = rot_dir(root->dir);
		return rot_esq(root);
	}
	return root;
}
void imprimirEmOrdem(TAVL *root){
	if (root != NULL){
		imprimirEmOrdem(root->esq);
		printf("%d ", root->chave);
		imprimirEmOrdem(root->dir);
	}
}
TAVL *procuraMenor(TAVL *atual){
	TAVL *no1 = atual;
	TAVL *no2 = atual->esq;
	while(no2!=NULL){
		no1=no2;
		no2=no2->esq;
	}
	return no1;
}
int remove_arv(TAVL *root, int valor){
	if(root==NULL){
		return 0;
	}
	int res;
	if(valor < root->chave){
		if((res=remove_arv(root->esq,valor))==1){
			if(get_fb(root)>=2){
				if(altura(root->dir->esq) <= altura(root->dir->dir)){
					rotacaoRR(root);
				}else{
					rotacaoRL(root);
				}
			}
		}
	}if(valor > root->chave){
		if((res=remove_arv(root->dir,valor))==1){
			if(get_fb(root)>=2){
				if(altura(root->esq->dir)<= altura(root->esq->esq)){
					rotacaoLL(root);
				}else{
					rotacaoLR(root);
				}
			}
		}
	}
	if(root->chave == valor){
		if((root->esq == NULL) || (root->dir == NULL)){
			TAVL *aux=root;
			if(root->esq != NULL){
				root=root->esq;
			}else{
				root=root->dir;
			}
		}else{
			TAVL *aux=procuraMenor(root->dir);
			root->chave=aux->chave;
			remove_arv(root->dir, root->chave);
			if(get_fb(root)>=2){
				if(altura(root->esq->dir) <= altura(root->esq->esq)){
					rotacaoLL(root);
				}else{
					rotacaoLR(root);
				}
			}
			return 1;
		}
		return res;
	}
	
}
int main(){
	TAVL *root = NULL;
	int num;
	while(scanf("%d",&num), num != 0){
		root = inserir(root,num);
	}
	if(root!= NULL){
		imprimirEmOrdem(root);
		printf("\n");
	}
	int aux;
	scanf("%d",&aux);
	while(aux!=0){
		remove_arv(root,aux);
		imprimirEmOrdem(root);
		printf("\n");
		printf("%d %d\n",altura(root), root->chave);
		scanf("%d",&aux);
	}
	
	return 0;
}
