#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

typedef struct AVLTree {
    int data;
    struct AVLTree *left;
    struct AVLTree *right;
} AVLTree;

bool treeIsEmpty(AVLTree *tree) {
    return tree == NULL;
}

AVLTree* createTree(int data, AVLTree *left, AVLTree *right) {
    AVLTree *newTree = (AVLTree*)malloc(sizeof(AVLTree));
    if(newTree == NULL) { exit(1); }

    newTree->data = data;
    newTree->left = left;
    newTree->right = right;
    return newTree;
}

AVLTree* destroyTree(AVLTree *tree) {
    if(!treeIsEmpty(tree)) {
        destroyTree(tree->left);
        destroyTree(tree->right);
        free(tree);
    }
    return NULL;
}

void showTree(AVLTree *tree) {
    if(!treeIsEmpty(tree)) {
        showTree(tree->left);
        printf("%d ", tree->data);
        showTree(tree->right);
    }
}

bool search(AVLTree *tree, int searchKey) {
    if(treeIsEmpty(tree)) {
        return false;
    }
    if(tree->data == searchKey) {
        return true;
    } else if (searchKey < tree->data) {
        return search(tree->left, searchKey);
    } else {
        return search(tree->right, searchKey);
    }
}

int max(AVLTree *tree) {
    AVLTree *aux;
    aux = tree;
    while(!treeIsEmpty(aux->right)) {
        aux = aux->right;
    }
    return aux->data;
}

AVLTree* rotateLeft(AVLTree *A) {
    AVLTree *B = A->right;
    A->right = B->left;
    B->left = A;
    return B;
}

AVLTree* rotateRight(AVLTree *A) {
    AVLTree *B = A->left;
    A->left = B->right;
    B->right = A;
    return B;
}

AVLTree* doubleRotateLeft(AVLTree *tree) {
    tree->right = rotateRight(tree->right);
    return rotateLeft(tree);
}

AVLTree* doubleRotateRight(AVLTree *tree) {
    tree->left = rotateLeft(tree->left);
    return rotateRight(tree);
}

int height(AVLTree *tree) {
    int leftHeight = 0, rightHeight = 0;
    if(treeIsEmpty(tree)) {
        return -1;
    } else {
        leftHeight = height(tree->left);
        rightHeight = height(tree->right);
        if(leftHeight >= rightHeight) {
            return leftHeight + 1;
        } else {
            return rightHeight + 1;
        }
    }
}

int calculateBalanceFactor(AVLTree *tree) {
    return height(tree->right) - height(tree->left);
}

AVLTree* balance(AVLTree *tree) {
    if (!treeIsEmpty(tree)){
        tree->left = balance(tree->left);
        tree->right = balance(tree->right);

        int balanceFactor = calculateBalanceFactor(tree);
        
        if(balanceFactor > 1) {
            if(calculateBalanceFactor(tree->right) >= 0) {
                return rotateLeft(tree);
            }
            else
            {
                return doubleRotateLeft(tree);
            }
        } else if(balanceFactor < -1) {
            if(calculateBalanceFactor(tree->left) <= 0) {
                return rotateRight(tree);
            }
            else
            {
                return doubleRotateRight(tree);
            }
        }
    }
    return tree;
}

AVLTree* _insert(AVLTree *tree, AVLTree *treeToInsert) {
    if(treeIsEmpty(tree)) {
        return treeToInsert;
    } else if((treeToInsert->data) < (tree->data)) {
        tree->left = _insert(tree->left, treeToInsert);
    } else if((treeToInsert->data) >= (tree->data)) {
        tree->right = _insert(tree->right, treeToInsert);
    }
    return tree;
}

void insert(AVLTree **tree, int data) {
    *tree = _insert(*tree, createTree(data, NULL, NULL));
    *tree = balance(*tree);
}

AVLTree* _removeTree(AVLTree* tree, int key) {
    AVLTree *aux;
    if(key < tree->data) {
        tree->left = _removeTree(tree->left, key);
    } else if(key > tree->data) {
        tree->right = _removeTree(tree->right, key);
    } else {
        if(treeIsEmpty(tree->left)) {
            aux = tree->right;
            free(tree);
            return aux;
        } else if(treeIsEmpty(tree->right)) {
            aux = tree->left;
            free(tree);
            return aux;
        } else {
            tree->data = max(tree->left);
            tree->left = _removeTree(tree->left, tree->data);
        }
    }
    return tree;
}

void removeTree(AVLTree **tree, int data) {
    *tree = _removeTree(*tree, data);
    *tree = balance(*tree);
}

bool verifyIfIsBalanced(AVLTree *tree) {
    int balanceFactor;
    if(treeIsEmpty(tree)) {
        return true;
    }

    balanceFactor = calculateBalanceFactor(tree);
    
    if(balanceFactor < -1 || balanceFactor > 1) {
        return false;
    } else {
        return verifyIfIsBalanced(tree->left) && verifyIfIsBalanced(tree->right);
    }
}

void showTreeData(AVLTree *tree) {
    if(!treeIsEmpty(tree)) {
        showTree(tree);
        printf("\n");
        printf("%d %d\n", height(tree), tree->data);
    } else {
        printf("0 0\n");
    }
}

int main() {
    AVLTree *tree;

    /*Lendo valores e os inserindo na árvore*/

    int buffer;
    scanf("%d", &buffer);
    if(buffer != 0) {
        tree = createTree(buffer, NULL, NULL);
        scanf("%d", &buffer);
        while(buffer != 0) {
            insert(&tree, buffer);
            scanf("%d", &buffer);
        }

        showTreeData(tree);

        /*Lendo valores e os removendo da árvore*/

        scanf("%d", &buffer);
        while(buffer != 0) {
            if(search(tree, buffer)) {
                removeTree(&tree, buffer);
                showTreeData(tree);
            }
            scanf("%d", &buffer);
        }
/*
        if(verifyIfIsBalanced(tree)) {
            puts("SIM");
        } else {
            puts("NAO");
        }
*/
        destroyTree(tree);
    }
    return 0;
}
