#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int FILHOE = 0, FILHOD = 0;

typedef struct avl TAVL;
struct avl
{
    int chave;
    TAVL* esq;
    TAVL* dir;
};

TAVL *remover_TAVL(TAVL*r, int x);

TAVL* criar_no(int valor)
{
    TAVL* no = (TAVL*) malloc(sizeof(TAVL));
    no->chave = valor;
    no->esq = NULL;
    no->dir = NULL;

    return no;
}

TAVL* buscaNo(TAVL* r, int v)
{
    if (r == NULL) return NULL;
    else if (r->chave > v) return buscaNo(r->esq,v);
    else if (r->chave < v) return buscaNo(r->dir,v);
    else return r;
}

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

TAVL* procuraMenor(TAVL* r)
{
    TAVL *aux = r;
    while (aux->dir != NULL)    //Procurar o nó mais a esquerda (menor nó da árvore).
    {
        aux = aux->dir;
    }
    //printf("aux: %d\n", aux->n);
    return aux;
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

TAVL *verifica_balanceamento(TAVL *r)
{
    int fb = get_fb(r);

    if (fb < -1)
    {
        if (get_fb(r->esq) > 0)        //Rotação dupla a direita.
        {
            r->esq = rot_esq(r->esq);
        }
        r = rot_dir(r);             //Rotação simples a esquerda.
    }
    else if (fb > 1)
    {
        if (get_fb(r->dir) < 0)        //Rotação dupla a esquerda..
        {
            r->dir = rot_dir(r->dir);
        }
        r = rot_esq(r);            //Rotação simples a direita.
    }

    return r;
}

//Função que remove um nó que é folha (não possui filhos).
TAVL *remover_folha(TAVL *r)
{
    //printf("remover_folha %d\n", r->chave);
    free(r);
    return NULL;
}

TAVL *remover_1filho_esquerda(TAVL *r)
{
    //printf("remover_1filho_esquerda\n");
    TAVL *aux = r->esq;
    free(r);
    return aux;
}

TAVL *remover_1filho_direita(TAVL *r)
{
    //printf("remover_1filho_direita\n");
    TAVL *aux = r->dir;
    free(r);
    return aux;
}

TAVL *remover_2filhos(TAVL *r)
{
    ///printf("remover_2filhos\n");
    TAVL *aux, *rm;
    int x;
    aux = procuraMenor(r->esq); 
    //printf("procura menor: %d\n", aux->chave);
    x = aux->chave;                    
    rm = remover_TAVL(r->esq, x); 
    //printf("r = remove: %d\n", rm->chave);
    r->chave = x;
	if(FILHOE){
        r->esq = rm;
    }
    if(FILHOD){
        r->dir = rm;
    }
    //printf("root %d\n", r->chave);
    return r;
}


TAVL *remover_no(TAVL *r)
{
    if (r->dir == NULL && r->esq == NULL)
    {
        r = remover_folha(r);
    }
    else
    {
        if (r->dir == NULL)
        {
            r = remover_1filho_esquerda(r);
			  FILHOE = 1;
        }
        else
        {
            if (r->esq == NULL)
            {
                r = remover_1filho_direita(r);
					FILHOD = 1;
            }
            else
            {
                r = remover_2filhos(r);
            }
        }
    }
    return r;
}


TAVL *remover_TAVL(TAVL *r, int x)
{
    if(r != NULL)
    {
        if (r->chave == x) 
        {
            r = remover_no(r); 
        }
        else
        {
            if (x < r->chave)
            {
                r->esq = remover_TAVL(r->esq, x);
            }
            else
            {
                r->dir = remover_TAVL(r->dir, x);
            }
            r = verifica_balanceamento(r);
        }
    }else{
        return NULL;
    }

    return r;
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

int main()
{
    TAVL* root = NULL;

    int num;
    while(scanf("%d",&num), num != 0)
    {
        root = inserir(root,num);
    }
    if(root!= NULL)
    {
        imprimirEmOrdem(root);
        printf("\n");
        printf("%d %d\n", altura(root)-1, root->chave);
    }

    while(scanf("%d",&num), num != 0)
    {
        TAVL* aux = buscaNo(root, num);
        if(aux)
        {
            TAVL* rm = remover_TAVL(root, num);
            imprimirEmOrdem(root);
            printf("\n");
            printf("%d %d\n", altura(root)-1, root->chave);
        }
    }

    return 0;
}
