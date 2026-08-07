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
// função para criar um nó
TAVL* criar_no(int valor)
{
  TAVL* no = (TAVL*) malloc(sizeof(TAVL));
  no->chave = valor;
  no->esq = NULL;
  no->dir = NULL;

  return no;
}

// função para pegar a altura de uma arvore, ou seja, o caminho mais longo da raiz até um folha.
int altura(TAVL* root)
{
  if(root==NULL) // se um a raiz é null, convenciona-se que a sua altura é -1.
  {
    return -1;
  }
  else // caso contrário, percorre a árvore recursivamente.
  {
    if(altura(root->esq) > altura(root->dir))
      return altura(root->esq) + 1;
    else
      return altura(root->dir) + 1;
  }
}


//função para obter o balanceamente de um determinado nó da árvore.
int get_fb(TAVL* no_arvore)
{
  if(no_arvore != NULL)
    return (altura(no_arvore->esq) - altura(no_arvore->dir));
  else
    return 0;
}

//rotação simples para a esquerda;
TAVL* rot_esq(TAVL* ponto)
{
  TAVL *Aux = ponto->dir;
  ponto->dir = Aux->esq;
  Aux->esq = ponto;

  return Aux;
}

//rotação simples para direita;
TAVL* rot_dir(TAVL* ponto)
{

  TAVL* Aux = ponto->esq;
  ponto->esq = Aux->dir;
  Aux->dir = ponto;

  return Aux;
}


// inserir um nó na árvore AVL de forma recursiva
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
  if (fb < -1 && chave < root->dir->chave)
  {
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
//função para remover o nó de um árvore avl, mas cada remoção verifica se a ele está balanceada.
TAVL * removeNo( TAVL *raiz, int chave){
  if ( raiz == NULL ) return NULL;
  else if ( raiz -> chave > chave ){
    raiz -> esq = removeNo(raiz -> esq, chave);
  }
  else if ( raiz -> chave < chave){
    raiz -> dir = removeNo( raiz -> dir, chave);
  }
  else{
    if ( raiz -> esq == NULL && raiz -> dir == NULL){
      free(raiz);
      raiz = NULL;
    }
    else if ( raiz -> esq == NULL){
      TAVL *t = raiz;
      raiz = raiz -> dir;
      free(t);
    }
    else if( raiz -> dir == NULL){
      TAVL *t = raiz;
      raiz = raiz -> esq;
      free(t);
    }
    else{
      TAVL *pai = raiz;
      TAVL *filho = raiz -> esq;
      while ( filho -> dir){
        pai = filho;
        filho = filho -> dir;
      }
      raiz -> chave = filho -> chave;
      filho -> chave = chave;
      raiz -> esq = removeNo(raiz ->esq, chave);
    }
  }
  return raiz;
}
int main(){
  TAVL* root = NULL;
  int dados, valor;
  valor = 1;
  while ( valor ){
    scanf("%d%*c",&dados);
    if ( dados == 0){
      valor = 0;
    }
    else {
      root = inserir(root,dados);
    }
  }
  valor = 1;
  int contador = 0;
  while ( valor ){
      scanf("%d%*c",&dados);
      if ( dados == 0 ){
        valor = 0;
      }
      else{
        if ( contador == 0 ){
          imprimirEmOrdem(root);
          printf("\n");
          printf("%d %d\n",altura(root), root->chave);
          removeNo(root,dados);
        }
        else{
          removeNo(root,dados);
          imprimirEmOrdem(root);
          printf("\n");
          printf("%d %d\n",altura(root), root->chave);
        }
      }
      contador ++;
  }
  return 0;
}