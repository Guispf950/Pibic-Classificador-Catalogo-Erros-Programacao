#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct avl{
  int chave;
  struct avl* esq;
  struct avl* dir;
}TAVL;

TAVL* criar_no(int valor){
  TAVL* no = (TAVL*) malloc(sizeof(TAVL));
  no->chave = valor;
  no->esq = NULL;
  no->dir = NULL;

  return no;
}

int altura(TAVL* root){
  if(root==NULL){
    return 0;
  }
  else{
    if(altura(root->esq) > altura(root->dir))
      return altura(root->esq) + 1;
    else
      return altura(root->dir) + 1;
  }
}

int get_fb(TAVL* no_arvore){
  if(no_arvore != NULL)
    return (altura(no_arvore->esq) - altura(no_arvore->dir));
  else
    return 0;
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

TAVL* busca (TAVL* r, int v){
  if (r == NULL) return NULL;
  else if (r->chave > v) return busca(r->esq,v);
  else if (r->chave < v) return busca(r->dir,v);
  else return r;
}

TAVL* inserir (TAVL* root, int chave) {
  if(root == NULL){
    root = criar_no(chave);
    return root;
  }
  else if(chave < root->chave)
      root->esq = inserir(root->esq,chave);
  else if(chave > root->chave)
      root->dir = inserir(root->dir,chave);

  int fb = get_fb(root);

  //rot simples para direita
  if (fb > 1 && chave < root->esq->chave)
      return rot_dir(root);

  //rot simples para esquerda
  if (fb < -1 && chave > root->dir->chave)
      return rot_esq(root);

  //rot dupla para direita
  if (fb > 1 && chave > root->esq->chave){
      root->esq = rot_esq(root->esq);
      return rot_dir(root);
  }
  //rot dupla para esquerda
  if (fb < -1 && chave < root->dir->chave){
      root->dir = rot_dir(root->dir);
      return rot_esq(root);
  }
  return root;
}

TAVL* rearranjo(TAVL* root){
  int fb = get_fb(root);
  if(fb > 1){
    root->esq = rearranjo(root->esq);
  }else if(fb < -1){
    root->dir = rearranjo(root->dir);
  }
  else{
    return root;
  }
	fb = get_fb(root);
	if(fb > 1){
		int hm = get_fb(root->esq);
		if(hm <= -1){
			root->esq = rot_esq(root->esq);
			return rot_dir(root);
		}else{
			return rot_dir(root);
		}
	}
	else if(fb < -1){
		int hm = get_fb(root->dir);
		if(hm >= 1){
			root->dir = rot_dir(root->dir);
			return rot_esq(root);
		}else{
			return rot_esq(root);
		}
	}
	return root;
}

TAVL* retira(TAVL* root, int chave){
  if (root == NULL) return NULL;
  else if (root->chave > chave){
    root->esq = retira(root->esq, chave);
  }
  else if (root->chave < chave){
    root->dir = retira(root->dir, chave);
  }
  else{
    TAVL* aux = root;
    TAVL* aux2 = root->esq;
	 while(aux2){
		 if(aux2->dir == NULL){
			 if(aux == root) aux->esq = NULL;
			 else if(aux2->esq != NULL){
				 aux->dir = aux2->esq;
				 aux2->esq = NULL;
			 }
			 else aux->dir = NULL;
		 }
		 aux = aux2;
		 aux2 = aux2->dir;
	 }
    if(aux == root){
      free(root);
      return NULL;
    }
    if(aux->esq == NULL) aux->esq = root->esq;
    if(aux->dir == NULL) aux->dir = root->dir;
    free(root);
    return rearranjo(aux);
  }
  return rearranjo(root);
}

void imprimirEmOrdem(TAVL *root){
  if (root != NULL){
    imprimirEmOrdem(root->esq);
    printf("%d ", root->chave);
    imprimirEmOrdem(root->dir);
  }
}

void imprimir(TAVL *root){
  imprimirEmOrdem(root);
  printf("\n%d %d\n", altura(root)-1, root->chave);
}

int main(){
  TAVL* root = NULL;
  int num;
  while(scanf("%d",&num), num != 0){
    root = inserir(root, num);
  }
  if(root) imprimir(root);
  while(scanf("%d",&num), num != 0){
    if(busca(root, num)){
      root = retira(root, num);
      if(root) imprimir(root);
    }
  }
  return 0;
}