#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct avl TAVL;
struct avl
{
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

//obter a "altura" da árvore é o mesmo de pegar o maior caminho até o fim do nó
int altura(TAVL* root){
	if(root==NULL){
    	return -1;
  	}else{
		if(altura(root->esq) > altura(root->dir))
      	return altura(root->esq) + 1;
    	else
      	return altura(root->dir) + 1;
  	}
}

//forma de obter o fator de balanceamento (FB)
int get_fb(TAVL* no_arvore){
	if(no_arvore != NULL)
   	return (altura(no_arvore->esq) - altura(no_arvore->dir));
  	else
   	return 0;
}

//rotacionar para esquerda
TAVL* rot_esq(TAVL* ponto)
{
  TAVL *Aux = ponto->dir;
  ponto->dir = Aux->esq;
  Aux->esq = ponto;

  return Aux;
}

//rotacionar para direita
TAVL* rot_dir(TAVL* ponto) 
{

  TAVL* Aux = ponto->esq;
  ponto->esq = Aux->dir;
  Aux->dir = ponto;

  return Aux;
}


// inserir na árvore AVL de forma recursiva
TAVL* inserir (TAVL* root, int chave) 
{
  if(root == NULL)
  {
    root = criar_no(chave);
    return root;
  }
  else if(chave < root->chave )
      root->esq = inserir(root->esq,chave);
  else if(chave > root->chave)
      root->dir = inserir(root->dir,chave);


  int fb = get_fb(root);
  //as rotações dependem do fb e do valor da chave

  //rot simples para direita
  if (fb > 1 && chave < root->esq->chave)
      return rot_dir(root);

  //rot simples para esquerda
  if (fb < -1 && chave > root->dir->chave)
      return rot_esq(root);

  //rot dupla para direita
  if (fb > 1 && chave > root->esq->chave)
  {
      root->esq =  rot_esq(root->esq);
      return rot_dir(root);
  }
  //rot dupla para esquerda
  if (fb < -1 && chave < root->dir->chave){
      root->dir = rot_dir(root->dir);
      return rot_esq(root);
  }
  return root;
}

void imprimirEmOrdem(TAVL *root)
{
  if (root != NULL)
  {
    imprimirEmOrdem(root->esq);
    printf("%d ", root->chave);
    imprimirEmOrdem(root->dir);
  }
}

TAVL* busca (TAVL* r, int v){
	if (r == NULL) return NULL;
	else if (r->chave > v) return busca(r->esq,v);
	else if (r->chave < v) return busca(r->dir,v);
	else return r;
}

TAVL* maxValueNode(TAVL* node){
   TAVL* current = node;
   while (current && current->dir != NULL)
		//printf("looking for leftmost node. Current: %d\n", current->chave);
   	current = current->dir;
	return current;
}


TAVL* removeNo(TAVL* root, int chave){
	if (!root)
		return root;
	else if (chave < root->chave)
		root->esq = removeNo(root->esq, chave);
	else if (chave > root->chave)
		root->dir = removeNo(root->dir, chave);
	else{
		if (!root->esq){
			//printf("Left empty. Node found: %d\n", root->chave);
			TAVL* tmp = root->dir;
			free(root);
			return tmp;
		}else if(!root->dir){
			//printf("Right empty. Node found: %d\n", root->chave);
			TAVL* tmp = root->esq;
			free(root);
			return tmp;
		}else{
			TAVL* tmp = maxValueNode(root->esq);
			root->chave = tmp->chave;
			root->esq = removeNo(root->esq, tmp->chave);
		}
	}
	
	int bf = get_fb(root);
	if (bf == 2 && get_fb(root->esq) >= 0)
		return rot_dir(root);
	else if (bf == 2 && get_fb(root->esq) == -1){
		root->esq = rot_esq(root->esq);
		return rot_dir(root);
	}else if (bf == -2 && get_fb(root->dir) <= 0)
		return rot_esq(root);
	else if(bf == -2 && get_fb(root->dir) == 1){
		root->dir = rot_dir(root->dir);
		return rot_esq(root);
	}
	return root;
}


int main(){
	TAVL* root = NULL;
	
	int num;
	//Le os dados para inserir na lista
	do{
		scanf("%d", &num);
		if (num){
			root = inserir(root, num);
		}
	} while (getchar() != '\n' && num!=0);
  	
	imprimirEmOrdem(root);
	printf("\n%d %d\n", altura(root), root->chave);
	
	do{
		scanf("%d", &num);
		if (num){
			if (busca(root, num)){
				root = removeNo(root, num);
				imprimirEmOrdem(root);
				printf("\n%d %d\n", altura(root), root->chave);
			}
		}
	} while (getchar() != '\n' && num != 0);
	
  	return 0;
}