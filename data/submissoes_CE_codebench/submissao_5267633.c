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

TAVL* removeNoAVL(TAVL* no, int r);

TAVL* criar_no(int valor)
{
    TAVL* no = (TAVL*) malloc(sizeof(TAVL));
    no->chave = valor;
    no->esq = NULL;
    no->dir = NULL;
    
    return no;
}

int altura(TAVL* root)
{
    if(root==NULL)
    {
        return 0;
    }
    else
    {
        if(altura(root->esq) > altura(root->dir)) return altura(root->esq) + 1;
        else return altura(root->dir) + 1;
    }
}

int get_fb(TAVL* no_arvore)
{
    if(no_arvore != NULL) return (altura(no_arvore->esq) - altura(no_arvore->dir));
    else return 0;
}

TAVL* rot_esq(TAVL* ponto)
{
    TAVL *Aux = ponto->dir;
    ponto->dir = Aux->esq;
    Aux->esq = ponto;
    
    return Aux;
}

TAVL* rot_dir(TAVL* ponto) 
{
    TAVL* Aux = ponto->esq;
    ponto->esq = Aux->dir;
    Aux->dir = ponto;
    
    return Aux;
}

TAVL* inserir (TAVL* root, int chave) 
{
    if(root == NULL)
    {
        root = criar_no(chave);
        return root;
    }
    else if(chave < root->chave) root->esq = inserir(root->esq,chave);
    else if(chave > root->chave) root->dir = inserir(root->dir,chave);
    
    int fb = get_fb(root);

    if(fb > 1 && chave < root->esq->chave) return rot_dir(root);

    if(fb < -1 && chave > root->dir->chave) return rot_esq(root);

    if (fb > 1 && chave > root->esq->chave)
    {
        root->esq =  rot_esq(root->esq);
        return rot_dir(root);
    }

    if (fb < -1 && chave < root->dir->chave)
    {
        root->dir = rot_dir(root->dir);
        return rot_esq(root);
    }

    return root;

}

TAVL* removeFolha(TAVL* no)
{
    free(no);
    return NULL;
}

TAVL* removeFilhoEsq(TAVL* no)
{
    TAVL* aux = no->esq;

    free(no);
    return aux;
}

TAVL* removeFilhoDir(TAVL* no)
{
    TAVL* aux = no->dir;

    free(no);
    return aux;
}

TAVL* menorNoArvore(TAVL* no)
{
    TAVL* aux = no;
    while (aux->dir != NULL)
    {
        aux = aux->dir;
    }
    return aux;
}

TAVL* removeFilho(TAVL* no) 
{
    TAVL* aux;
    int r;

    aux = menorNoArvore(no->esq);
    r = aux->chave;
    no = removeNoAVL(no, r);

    no->chave = r;
    return no;
}

TAVL* removeNo(TAVL* no) 
{
    if(no->dir == NULL && no->esq) 
    {
        no = removeFolha(no);
    }
    else
    {
        if(no->dir == NULL)
        {
            no = removeFilhoEsq(no);
        }
        else
        {
            if(no->esq == NULL)
            {
                no = removeFilhoDir(no);
            }
            else
            {
                no = removeFilho(no);
            }
        }
    }
    return no;
}

TAVL* removeNoAVL(TAVL* no, int r) 
{
    if(no == NULL) 
    {
        return 0;
    }

    if(no->chave == r) 
    {
        no = removeNo(no);
    }
    else
    {
        if(r < no->chave)
        {
            no->esq = removeNoAVL(no->esq, r);
        }
        else
        {
            no->dir = removeNoAVL(no->dir, r);
        }
        
        int fb = get_fb(no);
        
        if(fb > 1 && r < no->esq->chave) return rot_dir(no);
        if(fb < -1 && r > no->dir->chave) return rot_esq(no);
        
        if (fb > 1 && r > no->esq->chave)
        {
            no->esq =  rot_esq(no->esq);
            return rot_dir(no);
        }
        
        if (fb < -1 && r < no->dir->chave)
        {
            no->dir = rot_dir(no->dir);
            return rot_esq(no);
        }
    }
    return no;
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

int main()
{
    TAVL* root = NULL;
    
    int num;
    while(scanf("%d",&num), num != 0)
    {
        root = inserir(root,num);
    }

    imprimirArvore(root, 2);
    printf("%d ", altura(root) - 1);
    printf("%d\n", root->chave);

    int numR;
    TAVL *noRemovido;
    while(scanf("%d",&numR), numR != 0)
    {
        noRemovido = removeNoAVL(root, numR);
        imprimirArvore(root, 2);
        printf("%d ", altura(root) - 1);
        printf("%d\n", root->chave);
    }

    return 0;
}