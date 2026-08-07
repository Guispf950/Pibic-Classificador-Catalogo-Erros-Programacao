#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    false, true
} bool;

typedef int Data;

typedef struct Node {
    Data data;
    struct Node *left;
    struct Node *right;
} Node;

Node *newNode (Data data) {
    Node *node = (Node *)malloc(sizeof(Node));
    node->data = data;
    node->left = NULL;
    node->right = NULL;
    return node;
}

int getHeight (Node *root) {
    if (!root) return 0;
    else {
        if (getHeight(root->left) > getHeight(root->right)) 
            return (getHeight(root->left) + 1);
        else return (getHeight(root->right) + 1);
    }
}

int getBF (Node *node) {
    if (node) return (getHeight(node->left) - getHeight(node->right));
    else return 0;
}

Node *RL (Node *node) {
    Node *aux = node->right;
    node->right = aux->left;
    aux->left = node;
    return aux;
}

Node *RR (Node *node) {
    Node *aux = node->left;
    node->left = aux->right;
    aux->right = node;
    return aux;
}

Node *balance (Node *node) {
    int bf = getBF(node);
    Node *aux;

    if (bf > 1) {
        aux = node->left;
        bf = getBF(aux);

        if (bf < 0) node->left = RL(node->left); // Rotação Dupla L-R
        node = RR(node); // Rotação Simples Direita
    } else if (bf < -1) {
        aux = node->right;
        bf = getBF(aux);

        if (bf > 0) node->right = RR(node->right); // Rotação Dupla R-L
        node = RL(node); //Rotação Simples Esquerda
    }

    return node;
}

Node *insert (Node *root, Data data) {
    if (root == NULL) {
        root = newNode(data);
        return root;
    } else {
        Data tmp = root->data;
        if (data < root->data)
            root->left = insert(root->left, data);
        else root->right = insert(root->right, data);
    }

    return balance(root);
}

Node *largerValue (Node *node) {
    Node *n1 = node, *n2 = node->right;

    while (n2) {
        n1 = n2;
        n2 = n2->right;
    }
    
    return n1;
}

Node *remove_node (Node *node, Data data, bool *removed) {
    if (node == NULL) return NULL;

    Data currentData = node->data;
    if (data == currentData) {
        Node *tmp = node;
        *removed = true;
        if (node->left == NULL || node->right == NULL) {
            if (node->left != NULL) node = node->left;
            else node = node->right;
            free(tmp);
        } else {
            Node *aux = largerValue(node->left);
            node->data = aux->data;
            node->left = remove_node(node->left, node->data, removed);
        }
    } else if (data < currentData) node->left = remove_node(node->left, data, removed);
    else node->right = remove_node(node->right, data, removed);

    return balance(node);
}

bool isFirst = true;
void show (Node *node) {
    if (node) {
        show(node->left);
        if (isFirst) printf("%d", node->data);
        else printf(" %d", node->data);
        isFirst = false;
        show(node->right);
    }
}

int main (void) {
    Node *tree = NULL;
    Data data;

    while (scanf("%d", &data) && data) 
        tree = insert(tree, data);

    int h = getHeight(tree);
    bool removed = false;

    show(tree); 
    printf("\n%d %d\n", h - 1, tree->data);

    while (scanf("%d", &data) && data) {
        removed = false; isFirst = true;
        tree = remove_node(tree, data, &removed);

        if (removed) {
            h = getHeight(tree);
            show(tree); 
            printf("\n%d %d\n", h - 1, tree->data);
        }
    }   

    return 0;    
}