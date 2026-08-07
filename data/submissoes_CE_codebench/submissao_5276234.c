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
int altura(TAVL* root)
{
    if(root==NULL)
    {
        return 0;
    }
    else
    {
        if(altura(root->esq) > altura(root->dir))
            return altura(root->esq) + 1;
        else
            return altura(root->dir) + 1;
    }
}


//forma de obter o fator de balanceamento (FB)
int get_fb(TAVL* no_arvore)
{
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

void rot(TAVL* raiz) {
    rot_dir(raiz->esq);
    rot_esq(raiz);
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
    if (fb < -1 && chave < root->dir->chave)
    {
        root->dir = rot_dir(root->dir);
        return rot_esq(root);
    }

    return root;

}


void imprimirPreOrdem(TAVL* root)
{
    if(root != NULL)
    {
        printf("%d ",root->chave);
        imprimirPreOrdem(root->esq);
        imprimirPreOrdem(root->dir);

    }
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
void imprimirPosOrdem(TAVL *root)
{
    if (root != NULL)
    {
        imprimirPosOrdem(root->esq);
        imprimirPosOrdem(root->dir);
        printf("%d ", root->chave);
    }
}
void imprimirArvore(TAVL* root, int tipo)
{
    if(tipo == 1)
    {
        imprimirPreOrdem(root);
    }
    else if(tipo == 2)
    {
        imprimirEmOrdem(root);
    }
    else if(tipo == 3)
    {
        imprimirPosOrdem(root);
    }

    printf("\n");
}

TAVL* lerValores(TAVL* root) {
    int dado = 1, alt; 
    while(1) {
        scanf("%d%*c",&dado);
        if(dado == 0){
            break;
        }
        
        root = inserir(root,dado);
        //alt = altura(root);
        //printf("inseriu: %d, altura: %d\n",dado,alt);
    }
    return root;
}

void imprime(TAVL *a)
{
    if (a != NULL)
    {
        printf("%c ", a->chave); /* mostra raiz */
        imprime(a->esq);        /* mostra sae */
        imprime(a->dir);        /* mostra sad */
    }
}


TAVL* procuraMenor(TAVL* atual) {
    TAVL *n1 = atual;
    TAVL *n2 = atual->esq;
    while(n2 != NULL) {
        n1 = n2;
        n2 = n2->esq;
    }
    return n1;
}

int removeAVL(TAVL *raiz,int valor) {
    if (raiz == NULL)
    {
        printf("valor nao existe\n");
        return 0;
    }
    int res;
    if (valor < raiz->chave)
    {
        if ((res = removeAVL(raiz->esq,valor)) == 1)
        {
            if (get_fb(raiz) >= 1)
            {
                if (altura(raiz->dir->esq) <= altura(raiz->dir->dir))
                {
                    rot_esq(raiz);
                }
                else {
                    rot_dir(raiz);
                }
            }
        }
    }
    if (raiz->chave == valor) 
    {
        if ((raiz->esq == NULL || raiz->dir == NULL))
        {
            TAVL *oldNode = raiz;
            if (raiz->esq != NULL)
            {
                raiz = raiz->esq;
            }
            else{
                raiz = raiz->dir;
            }
            free(oldNode);  
        } else{
            TAVL* temp = procuraMenor(raiz->dir);
            raiz->chave = temp->chave;
            removeAVL(raiz->dir, raiz->chave);
            if (get_fb(raiz) >= 1)
            {
                if (altura(raiz->esq->dir) <= altura(raiz->esq->esq))
                {
                    rot_dir(raiz);
                }
                else {
                    rot(raiz);
                }
            }
            return 1;
        }
        return res;
    }
}

void removeValores(TAVL* root) {
    int dado = 1, alt; 
    while(1) {
        scanf("%d%*c",&dado);
        if(dado == 0){
            break;
        }
        
        if(removeAVL(root,dado)) {
            printf("removeu\n");
        }
        //alt = altura(root);
        //imprimirEmOrdem(root);

        //printf("\n%d %d\n",alt,root->chave);
    }
    //return root;
}
int main()
{
    int dado;
    scanf("%d%*c",&dado);
    TAVL* root = criar_no(dado);
    root = lerValores(root);
    removeValores(root);
    imprimirEmOrdem(root);

    printf("\n%d %d\n",altura(root),root->chave);
}