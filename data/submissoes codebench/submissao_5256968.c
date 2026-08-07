#include <stdio.h>
#include <stdlib.h>

#ifndef MAX
  #define MAX(x,y) (x>y?x:y)
#endif

typedef struct NodeAVL{
  int data, height;
  struct NodeAVL *left, *right;
}NodeAVL;

NodeAVL* node_avl_new(int data){
  NodeAVL *nd = (NodeAVL*) malloc(sizeof(NodeAVL));
  nd->data = data;
  nd->height = 0;
  nd->left = nd->right = NULL;
  return nd;
}

int exist;

void node_avl_free_all(NodeAVL *root){
  if(root==NULL) return;
  node_avl_free_all(root->left);
  node_avl_free_all(root->right);
  free(root);
}

int node_avl_height(NodeAVL *root){
  return root ? root->height : -1;
}

//Get balance factor (leftHeight - rightHeight)
int node_avl_bf(NodeAVL *root){
  return root ? node_avl_height(root->left) - node_avl_height(root->right) : 0;
}

NodeAVL* node_avl_rotate_right(NodeAVL *x){
  if(x==NULL || x->left==NULL) return x;

  NodeAVL *y = x->left;
  x->left = y->right;
  y->right = x;

  x->height = MAX(node_avl_height(x->left), node_avl_height(x->right))+1;
  y->height =MAX(node_avl_height(y->left), node_avl_height(y->right))+1;

  return y;
}

NodeAVL* node_avl_rotate_left(NodeAVL *x){
  if(x==NULL || x->right==NULL) return x;

  NodeAVL *y = x->right;
  x->right = y->left;
  y->left = x;

  x->height = MAX(node_avl_height(x->left), node_avl_height(x->right))+1;
  y->height =MAX(node_avl_height(y->left), node_avl_height(y->right))+1;

  return y;
}

NodeAVL* node_avl_balance(NodeAVL *root){
  if(root==NULL) return root;

  root->height = MAX(node_avl_height(root->left), node_avl_height(root->right))+1;

  int bf = node_avl_bf(root);
  // printf("Balanceando %d | ", root->data);
  if(bf > 1){ //unbalanced left
    // printf("Desbalanceado esquerda ");
    if(node_avl_bf(root->left)<0){ //unbalanced on left right
      root->left = node_avl_rotate_left(root->left);
      // printf("direita\n");
    }
    // else printf("esquerda\n");
    return node_avl_rotate_right(root);
  }
  else if(bf < -1){ //unbalanced right
    // printf("Desbalanceado direita ");
    if(node_avl_bf(root->right)>0){ //unbalanced on right left
      root->right = node_avl_rotate_right(root->right);
      // printf("esquerda\n");
    }
    // else printf("direita\n");
    return node_avl_rotate_left(root);
  }

  // printf("Nao desbalanceado\n");
  return root;
}

NodeAVL* node_avl_insert(NodeAVL *root, int data){
  if(root==NULL) return node_avl_new(data);
  else if(data==root->data) return root;
  else if(data < root->data) root->left = node_avl_insert(root->left, data);
  else root->right = node_avl_insert(root->right, data);

  return node_avl_balance(root);
}

NodeAVL* node_avl_max_value(NodeAVL *root){
  if(root!=NULL)
    while(root->right) root = root->right;
  return root;
}

NodeAVL* node_avl_remove(NodeAVL *root, int data){
  if(root==NULL) return root;
  else if(data < root->data) root->left = node_avl_remove(root->left, data);
  else if(data > root->data) root->right = node_avl_remove(root->right, data);
  else{
    exist = 1;
    if(root->left!=NULL && root->right!=NULL){ // 2 childs
      NodeAVL *maxValueNd = node_avl_max_value(root->left);
      root->data = maxValueNd->data;
      root->left = node_avl_remove(root->left, root->data);
    }
    else{ //1 or 0 childs
      NodeAVL *aux = root->left ? root->left : root->right;
      if(aux) *root = *aux;
      else{
        aux = root;
        root = NULL;
      }
      free(aux);
    }
  }
  return node_avl_balance(root);
}

// void node_avl_print_prefix(NodeAVL *root){
//   if(root==NULL) return;
//   printf("%d ", root->data);
//   node_avl_print_prefix(root->left);
//   node_avl_print_prefix(root->right);
// }

void node_avl_print_infix(NodeAVL *root){
  if(root==NULL) return;
  node_avl_print_infix(root->left);
  printf("%d ", root->data);
  node_avl_print_infix(root->right);
}

int main(){
  NodeAVL *root = NULL;
  int x;

  do{
    scanf("%d", &x);
    if(x==0) break;
    // printf("\nInserindo %d:\n", x);
    root = node_avl_insert(root, x);
    // printf("root: %d\n", root->data);
  }while(x!=0);

  node_avl_print_infix(root);  printf("\n");
  if(root==NULL) printf("-1 0\n");
  else printf("%d %d\n", root->height, root->data);
  // printf("\n%d %d\n", root->height, root->data);

  do{
    scanf("%d", &x);
    if(x==0) break;
    exist=0;
    root = node_avl_remove(root, x);
    if(!exist) continue;
    node_avl_print_infix(root); printf("\n");
    // node_avl_print_prefix(root); printf("\n");
    if(root==NULL) printf("-1 0\n");
    else printf("%d %d\n", root->height, root->data);
  }while(x!=0);

  return 0;
}