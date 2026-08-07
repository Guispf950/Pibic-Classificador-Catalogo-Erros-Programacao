#include "stdio.h"
#include "stdlib.h"

typedef struct tree TTree;
struct tree{
  int key;
  int height;
  TTree *left;
  TTree *right;
};

TTree *init(){
  return NULL;
}

int heightTree (TTree *root){
  if (root == NULL){
    return -1;
  }
  else{
    return root->height;
  }
}

int major (int a, int b){
  if (a > b){
    return a;
  }
  else if (b > a){
    return b;
  }
}

TTree *minor (TTree *avl){
  TTree *curr = avl;
  while (curr->left){
    curr = curr->left;
  }
  return curr;
}

TTree* createNode (int data){
    TTree* node = (TTree*)malloc(sizeof(TTree));
    node->key = data;
    node->left = NULL;
    node->right = NULL;
    node->height = 0;
    return node;
}

TTree *rightRot (TTree *n){
    TTree *aux = n->left;
    TTree *node2 = aux->right;
    aux->right = n;
    n->left = node2;
    n->height = major(heightTree(n->left), heightTree(n->right)) + 1;
    aux->height = major(heightTree(aux->left), heightTree(aux->right)) + 1;
    return aux;
}

TTree *leftRot (TTree *p){
    TTree *aux = p->right;
    TTree *aux2 = aux->left;
    aux->left = p;
    p->right = aux2;
    p->height = major(heightTree(p->left), heightTree(p->right)) + 1;
    aux->height = major(heightTree(aux->left), heightTree(aux->right)) + 1;
    return aux;
}

int bFact (TTree *node){
    if (node == NULL){
      return 0;
    }
    else{
      return heightTree(node->left) - heightTree(node->right);
    }
}

TTree *insertNode(TTree *avl, int data)
{
    if (avl == NULL){
      return(createNode(data));
    }
    if (data < avl->key){
      avl->left  = insertNode(avl->left, data);
    }
    else if (data > avl->key){
      avl->right = insertNode(avl->right, data);
    }
    else{
      return avl;
    }
    avl->height = major(heightTree(avl->left), heightTree(avl->right)) + 1;
    int b = bFact(avl);
    if ((b > 1) && (data < avl->left->key)){
      return rightRot(avl);
    }
    else if ((b < -1) && (data > avl->right->key)){
      return leftRot(avl);
    }
    else if ((b > 1) && (data > avl->left->key)){
        avl->left =  leftRot(avl->left);
        return rightRot(avl);
    }

    else if ((b < -1) && (data < avl->right->key)){
        avl->right = rightRot(avl->right);
        return leftRot(avl);
    }
    return avl;
}

TTree *searchNode(int key, TTree *root){
  if (root == NULL){
    return NULL;
  }
  if (root->key == key){
    return root;
  }
  else if (root->key > key){
    return (searchNode(key, root->left));
  }
  else{
    return (searchNode(key, root->right));
  }
}

TTree *removeNode(TTree *avl, int data)
{
    if (avl == NULL){
      return avl;
    }
    if(searchNode(data,avl) == NULL){
      return avl;
    }

    if (data < avl->key){
      avl->left = removeNode(avl->left, data);
    }

    else if(data > avl->key){
        avl->right = removeNode(avl->right, data);
    }
    else{
        if((avl->left == NULL) || (avl->right == NULL)){
          TTree *aux = avl;
          if (avl->left != NULL){
              avl = avl->left;
          }
          else{
            avl = avl->right;
          }
          free(aux);
        }
        else{
          TTree* aux = minor(avl->right);
          avl->key = aux->key;
          avl->right = removeNode(avl->right, aux->key);
        }
    }
    if (avl == NULL){
      return avl;
    }
    avl->height = major(heightTree(avl->left), heightTree(avl->right)) + 1;
    int b = bFact(avl);
    if ((b > 1) && (bFact(avl->left) >= 0)){
      return rightRot(avl);
    }
    if ((b > 1) && (bFact(avl->left) < 0)){
        avl->left =  leftRot(avl->left);
        return rightRot(avl);
    }
    if ((b < -1) && (bFact(avl->right) <= 0)){
      return leftRot(avl);
    }
    if ((b < -1) && (bFact(avl->right) > 0)){
        avl->right = rightRot(avl->right);
        return leftRot(avl);
    }
    return avl;
}

void printTree (TTree *avl){
  if (avl != NULL){
    printTree(avl->left);
    printf("%d ", avl->key);
    printTree(avl->right);
  }
}

int main()
{
  TTree *root = init();
  TTree *sub = init();
  int num, rem;

  scanf("%d",&num);
  while(num != 0){
    root = insertNode(root,num);
    scanf("%d",&num);
  }

  printTree(root);
  printf("\n%d ",heightTree(root));
  printf("%d\n",root->key);

  scanf("%d",&rem);
  while(rem != 0){
      root = removeNode(root,rem);
      printTree(root);
      printf("\n%d ",heightTree(root));
      printf("%d\n",root->key);

    scanf("%d",&rem);
  }
  return 0;
}