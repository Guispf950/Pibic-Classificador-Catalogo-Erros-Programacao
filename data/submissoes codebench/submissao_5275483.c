#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct No
{
    int Id; //Valor que é informado para o nó
    struct No *Esquerda; //Ligação com outro nó(valor) pela esquerda
    struct No *Direita; //Ligação com outro nó(valor) pela direita
    int Altura; //Altura do Nó
} No;

/* Função que verifica e imprime na tela a altura da árvore ou do nó */
int Altura(No *Raiz)
{
    if (Raiz == NULL) //Se raiz for nulo
        return -1; //retorna 0
    return Raiz-> Altura; //Senão usa recursividade
}

/* Função que retorna o fator de balanceamento do nó */
int Balanceamento(No *Raiz)
{
    if (Raiz == NULL)
    return 0;
    return Altura(Raiz-> Esquerda) - Altura(Raiz-> Direita);
}

/* Função que retorna o maior valor entre dois inteiros (Utilizado pelas rotações */
int Maior(int a, int b);

/* Função que retorna o maior valor entre dois inteiros (Utilizado pelas rotações */
int Maior(int a, int b)
{
    return (a > b)? a : b;
}

/* Função para a rotação da sub-árvore (à direita) */
No *RotDir(No *Raiz)
{
    No *AuxiliarEsquerda = Raiz-> Esquerda;
    No *AuxiliarDireita = AuxiliarEsquerda-> Direita;
 
    // Realizando rotação
    AuxiliarEsquerda-> Direita = Raiz;
    Raiz-> Esquerda = AuxiliarDireita;
 
    // Atualizando alturas
    Raiz-> Altura = Maior(Altura(Raiz-> Esquerda), Altura(Raiz-> Direita))+1;
    AuxiliarEsquerda-> Altura = Maior(Altura(AuxiliarEsquerda-> Esquerda), Altura(AuxiliarEsquerda-> Direita))+1;
 
    // Retornando a nova raiz (Raiz alterada)
    return AuxiliarEsquerda;
}
 
/* Função para a rotação da sub-árvore (à esquerda) */
No *RotEsq(No *Raiz)
{
    No *AuxiliarDireita = Raiz-> Direita;
    No *AuxiliarEsquerda = AuxiliarDireita-> Esquerda;
 
    // Realizando rotação
    AuxiliarDireita-> Esquerda = Raiz;
    Raiz-> Direita = AuxiliarEsquerda;
 
    // Atualizando alturas
    Raiz->Altura = Maior(Altura(Raiz-> Esquerda), Altura(Raiz-> Direita))+1;
    AuxiliarDireita->Altura = Maior(Altura(AuxiliarDireita-> Esquerda), Altura(AuxiliarDireita-> Direita))+1;
 
    // Retornando a nova raiz (Raiz alterada)
    return AuxiliarDireita;
}

/* Função para verificar se o ponteiro Raiz do tipo No (registro) é nulo */
int IsNull(No *Raiz) //Podia ser feito sem ela, mas dava mais trabalho pra fazer toda vez que fosse preciso verificar isso
{
	return (Raiz == (No*)NULL); //Sempre retorna nulo se for
}


/* Função auxiliar que aloca um novo nó para a chava informada - Chamada pela função AdicionarNo */
No* NovoNo(int Id)
{
    No* Raiz = (No*)malloc(sizeof(No)); //Aloca espaço na memória para o registro
    Raiz-> Id = Id; //Id de Raiz recebe a chave informada pelo usuário
    Raiz-> Esquerda = NULL; // Como o nó é novo -> Esquerda e -> Direita apontam para nulo
    Raiz-> Direita = NULL;
    Raiz-> Altura = 0;  // O novo nó inserido é inicialmente uma folha portanto sua altura é 1
    return(Raiz); //Retorna a Raiz
}

/* Função que insere um novo Nó - Utiliza a função auxiliar NovoNo */
No* AdicionarNo(No *Raiz, int Id)
{
    /* Passo 1 - Executa a inserção normal */
    if(Raiz == NULL) //Se a Raiz é nula(Vazia)
    {
        return(NovoNo(Id)); //Chama a função auxiliar que insere a chave informada pelo usuário
    }
else
    if(Raiz != NULL) //Se a Raiz não for nula(Vazia)
    {
        if(Id < Raiz-> Id) //Verifica se a chave informada pelo usuário é menor que a chave da Raiz
        {
            Raiz-> Esquerda  = AdicionarNo(Raiz-> Esquerda, Id); //se for menor, chama novamente a função(recursividade), fazendo a última chave(esquerda) apontar para a nova chave
        }
     //Senão (veja linha abaixo)
        if(Id > Raiz-> Id) //Verifica se a chave informada pelo usuário é maior que a chave da Raiz
        {
            Raiz-> Direita = AdicionarNo(Raiz-> Direita, Id); //senão for menor, é maior e chama novamente a função(recursividade), fazendo a última chave(direita) apontar para a nova chave
        }
 
        /* Passo 2 - Atualiza a altura do novo nó (em relação ao anterior) */
        Raiz-> Altura = Maior(Altura(Raiz-> Esquerda), Altura(Raiz-> Direita)) + 1;
 
        /* Passo 3 - Declarada uma váriável inteira que tem por objetivo obter o fator de balanceamento deste nó em relação ao anterior(pai) para saber se a arvore ficou desbalanceada*/
        int fb = Balanceamento(Raiz); //Verifica o fator de balanceamento
 
        //Se o novo nó causou desbalanceamento da árvore, será necessário obter o balanceamento por meio de uma das 4 formas (dependendo do caso)

        //Rotação simples à esquerda
        if (fb > 1 && Id < Raiz-> Esquerda-> Id) //Se o fator de balanceamento da Raiz for maior que 1 e o Id informado pelo usuário for menor que o Id que está na Raiz -> Esquerda
            return RotDir(Raiz); //Retorna a Raiz, depois de aplicada a Rotação à Direita(Função)
 
        //Rotação simples à direita
        if (fb < -1 && Id > Raiz-> Direita-> Id)
            return RotEsq(Raiz);
 
        //Rotação dupla à esquerda
        if (fb > 1 && Id > Raiz-> Esquerda-> Id)
        {
            Raiz-> Esquerda =  RotEsq(Raiz-> Esquerda);
            return RotDir(Raiz);
        }
 
        //Rotação dupla à direita
        if (fb < -1 && Id < Raiz-> Direita-> Id)
        {
            Raiz-> Direita = RotDir(Raiz-> Direita);
            return RotEsq(Raiz);
        } //Fim das rotações
 
        /* Passo 4 - Retorna a nova Raiz(alterada) */
        return Raiz;
    }
}

/* Função para buscar um nó e saber se um valor existe na árvore */
No* BuscarNo(No *Raiz, int Id)
{
    if (Raiz == (No*) NULL) //Se Raiz for igual a nulo
        return NULL; //Retorna Nulo
    
    if (Raiz-> Id == Id) //Se Id de Raiz for igual a Id passado por parâmetro
        return Raiz; //Retorna a própria Raiz pois não há nada a ser feito pois o valor já existe na árvore e não vamos duplicar esse bagulho, he he, tô gostando dessa parada Brendon
    
    if (Id > Raiz-> Id) //Se Id(parâmetro) for maior que Id de Raiz
        return BuscarNo(Raiz-> Direita, Id); //Chama novamente a função (recursividade) para iserir o valor a direita
    else if (Id < Raiz-> Id) //Caso não seja Maior, então é menor e
        return BuscarNo(Raiz-> Esquerda, Id); //chama novamente a função para inserir a esquerda informando os novos parâmetros
}

/* Procedimento para exibir (imprimir) os valores na ordem em que foram inseridos aplicando recursividade */
void imprimirPreOrdem(No *NoAtual)
{
    if(NoAtual == (No*) NULL) //Se o ponteiro NoAtual do Tipo No(registro) for nulo
        return; //Retorna Nulo
  //Senão
    printf("%d ", NoAtual->Id ); //Imprime um inteiro Id de Atual
    imprimirPreOrdem(NoAtual-> Esquerda); //E chama novamente a função para imprimir esquerda caso não seja nulo
    imprimirPreOrdem(NoAtual-> Direita); //E a direita caso não seja nulo
}

/* Procedimento para exibir (imprimir) os valores na ordem (maior e menor ao lado do valor) em que foram inseridos aplicando recursividade */
void imprimirPosOrdem(No *NoAtual)
{
    if (NoAtual == (No*) NULL) //Se o ponteiro passado como parâmentro for nulo
        return; //Retorna nulo
  //Senão
    imprimirPosOrdem(NoAtual-> Esquerda); //Chama novamente a função apontando para a esquerda
    imprimirPosOrdem(NoAtual-> Direita); //E depois para a direita
    printf("%d ", NoAtual->Id ); //imprimindo o valor
}

/* Procedimento para exibir (imprimir) os valores na ordem em que foram inseridos (tipo pré-ordem) aplicando recursividade */
void imprimirEmOrdem(No *NoAtual) //Varredura e-r-d (= inorder traversal = percurso em in-ordem) Ordem Raiz-Esquerda_Direita.
{
    if (NoAtual == (No*) NULL) //Se o ponteiro NoAtual do tipo No(registro) for nulo
        return; //Retorna nulo
  //Senão  
    imprimirEmOrdem(NoAtual-> Esquerda); //Senão chama novamente a função indo para a esquerda
    printf("%d ", NoAtual->Id ); //Imprimindo o Id
    imprimirEmOrdem(NoAtual-> Direita); //E depois chamando novamente a função indo para a direita
}


void imprimirArvore(No* root, int tipo)
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


/* Função auxiliar(será utilizada pela função RemoverNo) que retorna o menor valor(Id, ou chave) encontrado na árvore */
No* MenorId(No *Raiz)
{
    No *Atual = Raiz; //Variável Auxiliar do tipo No(registro) é igual a Raiz
 
    /* Repetição(Laço) para baixo até encontrar a folha mais a esquerda(Menor valor) (A árvore já está balanceada aqui)*/
    while (Atual-> Esquerda != NULL) //Enquanto esquerda de Atual não for Nulo
        Atual = Atual-> Esquerda; //Atual recebe (é igual) a Atual -> Esquerda (desce um nível na árvore)
 
    return Atual; //retorna Atual
}

int busca(No* a, int v)
{
  	if (a==NULL) return 0;
	if(a->Id == v) return 1;
	else{
		if (a->Id > v){
			return busca(a->Esquerda, v);
		}else
			return busca(a->Direita,v);
	}
}
No* MaiorId(No *Raiz)
{
    No *Atual = Raiz; //Variável Auxiliar do tipo No(registro) é igual a Raiz
 
    /* Repetição(Laço) para baixo até encontrar a folha mais a direita (Maior valor) (A árvore já está balanceada aqui)*/
    while (Atual->Direita != NULL) //Enquanto esquerda de Atual não for Nulo
        Atual = Atual->Direita; //Atual recebe (é igual) a Atual -> Esquerda (desce um nível na árvore)
 
    return Atual; //retorna Atual
}

/* Função para remover o nó da árvore sem ponteiro para ponteiro */
No* RemoverNo(No *Raiz, int Id)
{
    /* Passo 1 - Executa a remoção normal */
	if (Raiz == NULL)
        return Raiz;
   if ( Id < Raiz->Id ) //Verifica se a chave informada pelo usuário é menor que a chave da Raiz
        Raiz->Esquerda = RemoverNo(Raiz->Esquerda, Id); //se for menor, chama novamente a função(recursividade), fazendo a última chave(esquerda) apontar para a nova chave

	else //Senão (veja linha abaixo)

		if( Id > Raiz->Id ) //Verifica se a chave informada pelo usuário é maior que a chave da Raiz
        Raiz->Direita = RemoverNo(Raiz->Direita, Id); //senão for menor, é maior e chama novamente a função(recursividade), fazendo a última chave(direita) apontar para a nova chave
 
    	else //Se não é nenhum dos casos acima (maior ou menor), então é igual e este será o nó a ser removido
    	{
			if( (Raiz->Esquerda == NULL) || (Raiz->Direita == NULL) ) //Verifica se o nó tem pelo menos 1 filho (folha)
			{
            No *Temp = Raiz->Esquerda ? Raiz->Esquerda : Raiz->Direita;
 
            if(Temp == NULL) //Casos de não ter filho
            {
                Temp = Raiz;
                Raiz = NULL;
            }
            else //Senão, caso tenha 1 filho
             *Raiz = *Temp; //Copia o conteúdo do filho não vazi para a Raiz
 
            free(Temp); //Libera o registro (nó) temporário
        }
        else
        {
            //Caso o nó tenha 2 filhos, obter o menor Id da sub-árvore direita (poderia ser o maior da sub-árvore esquerda).
            No *Temp = MaiorId(Raiz->Esquerda);
 
            //Copia o valor de Id de Temp para a Raiz
            Raiz->Id = Temp->Id;
 
            //E a direita de raiz passará a apontar para o resultado da função RemoverNo passando como parâmetros a direita de Raiz e o Id de Temp
            Raiz->Esquerda = RemoverNo(Raiz->Esquerda, Temp->Id);
        }
    }

    if (Raiz == NULL) //Se a árvore for nula
      return Raiz; //Retorna ela própria
 
    /* Passo 2 - Atualiza a altura do novo nó (em relação ao anterior) */
    Raiz->Altura = Maior(Altura(Raiz->Esquerda), Altura(Raiz->Direita)) + 1;
 
    /* Passo 3 - Declarada uma váriável inteira que tem por objetivo obter o fator de balanceamento deste nó em relação ao anterior(pai) para saber se a arvore ficou desbalanceada*/
    int fb = Balanceamento(Raiz);
 
    //Se o novo nó causou desbalanceamento da árvore, será necessário obter o balanceamento por meio de uma das 4 formas (dependendo do caso)
 
    //Rotação simples à esquerda
    if (fb > 1 && Balanceamento(Raiz->Esquerda) >= 0)
        return RotDir(Raiz);
 
    //Rotação dupla à esquerda
    if (fb > 1 && Balanceamento(Raiz->Esquerda) < 0)
    {
        Raiz->Esquerda =  RotEsq(Raiz->Esquerda);
        return RotDir(Raiz);
    }
 
    //Rotação simples à direita
    if (fb < -1 && Balanceamento(Raiz->Direita) <= 0)
        return RotEsq(Raiz);
 
    //Rotação dupla à direita
    if (fb < -1 && Balanceamento(Raiz->Direita) > 0)
    {
        Raiz->Direita = RotDir(Raiz->Direita);
        return RotEsq(Raiz);
    }
 			
   return Raiz;
}

/* Procedimento para remoção da árvore completa utilizando ponteiro para ponteiro*/
No* RemoverAVL(No *Raiz)
{
    if(Raiz != NULL)
    {
    	No *Menor = MenorId(Raiz);
    	Raiz = RemoverNo(Raiz, Menor->Id);
    	Raiz = RemoverAVL(Raiz);
    }
else
	free(Raiz);
    return NULL;
}

int main(){
	int novo;
	scanf("%d", &novo);
	No *raiz= NULL;

	while(novo!=0){
		raiz= AdicionarNo(raiz, novo);
		scanf("%d", &novo);
	}
	
	imprimirArvore(raiz, 2); // infixada = tipo 2;
	printf("%d %d\n", Altura(raiz), raiz->Id);
	
	int valor;
	scanf("%d", &valor);
	while(valor!=0){
		if(busca(raiz, valor)==1){
			raiz= RemoverNo(raiz, valor);
			imprimirArvore(raiz, 2); // infixada = tipo 2;
			printf("%d %d\n", Altura(raiz), raiz->Id);
		}
		
		
		scanf("%d", &valor);
	}
	
	
	
	
	
	return 0;
}