// C program to delete a node from AVL Tree
#include<stdio.h>
#include<stdlib.h>

// An AVL tree node
struct Node
{
	int key;
	struct Node *left;
	struct Node *right;
	int height;
};

int searchTree(struct Node *a, int n)
{
	if (a == NULL)
	{
		return 0; /* não encontrou */
	}
	else
	{
		return a->key == n ||
			   searchTree(a->left, n) ||
			   searchTree(a->right, n);
	}
}

// A utility function to get maxValueimum of two integers
int maxValue(int a, int b);

// A utility function to get height of the tree
int height(struct Node *N)
{
	if (N == NULL)
		return 0;
	return N->height;
}

// A utility function to get maxValueimum of two integers
int maxValue(int a, int b)
{
	return (a > b)? a : b;
}

/* Helper function that allocates a new node with the given key and
	NULL left and right pointers. */
struct Node* newNode(int key)
{
	struct Node* node = (struct Node*)
						malloc(sizeof(struct Node));
	node->key = key;
	node->left = NULL;
	node->right = NULL;
	node->height = 1; // new node is initially added at leaf
	return(node);
}

// A utility function to right rotate subtree rooted with y
// See the diagram given above.
struct Node *rightRotate(struct Node *y)
{
	struct Node *x = y->left;
	struct Node *T2 = x->right;

	// Perform rotation
	x->right = y;
	y->left = T2;

	// Update heights
	y->height = maxValue(height(y->left), height(y->right))+1;
	x->height = maxValue(height(x->left), height(x->right))+1;

	// Return new root
	return x;
}

// A utility function to left rotate subtree rooted with x
// See the diagram given above.
struct Node *leftRotate(struct Node *x)
{
	struct Node *y = x->right;
	struct Node *T2 = y->left;

	// Perform rotation
	y->left = x;
	x->right = T2;

	// Update heights
	x->height = maxValue(height(x->left), height(x->right))+1;
	y->height = maxValue(height(y->left), height(y->right))+1;

	// Return new root
	return y;
}

// Get Balance factor of node N
int getBalance(struct Node *N)
{
	if (N == NULL)
		return 0;
	return height(N->left) - height(N->right);
}

struct Node* insert(struct Node* node, int key)
{
	/* 1. Perform the normal BST rotation */
	if (node == NULL)
		return(newNode(key));

	if (key < node->key)
		node->left = insert(node->left, key);
	else if (key > node->key)
		node->right = insert(node->right, key);
	else // Equal keys not allowed
		return node;

	/* 2. Update height of this ancestor node */
	node->height = 1 + maxValue(height(node->left),
						height(node->right));

	/* 3. Get the balance factor of this ancestor
		node to check whether this node became
		unbalanced */
	int balance = getBalance(node);

	// If this node becomes unbalanced, then there are 4 cases

	// Left Left Case
	if (balance > 1 && key < node->left->key)
		return rightRotate(node);

	// Right Right Case
	if (balance < -1 && key > node->right->key)
		return leftRotate(node);

	// Left Right Case
	if (balance > 1 && key > node->left->key)
	{
		node->left = leftRotate(node->left);
		return rightRotate(node);
	}

	// Right Left Case
	if (balance < -1 && key < node->right->key)
	{
		node->right = rightRotate(node->right);
		return leftRotate(node);
	}

	/* return the (unchanged) node pointer */
	return node;
}

/* Given a non-empty binary search tree, return the
node with minimum key value found in that tree.
Note that the entire tree does not need to be
searched. */
struct Node * minValueNode(struct Node* node)
{
	struct Node* current = node;

	/* loop down to find the leftmost leaf */
	while (current->left != NULL)
		current = current->left;

	return current;
}

// Recursive function to delete a node with given key
// from subtree with given root. It returns root of
// the modified subtree.
struct Node* deleteNode(struct Node* r, int key)
{
	if (r == NULL)
		return NULL;
	else if (r->key > key)
		r->left = deleteNode(r->left, key);
	else if (r->key < key) {
		r->right = deleteNode(r->right, key);	
	}
	else { // Achou!
		/* elemento sem filhos */
		if (r->left == NULL && r->right == NULL) {
			free (r);
			r = NULL;
		}
		/* só tem filho à righteita */
		else if (r->left == NULL) {
			struct Node* t = r;
			r = r->right;
			free (t);
		}
		/* só tem filho à leftuerda */
		else if (r->right == NULL) {
			struct Node* t = r;
			r = r->left;
			free (t);
		}
		/* tem os dois filhos */
		else {
			struct Node* pai = r;
			struct Node* f = r->left;
			while (f->right != NULL) {
				pai = f;
				f = f->right;
			}
			/* troca as informações */
			r->key = f->key;
			f->key = key;
			r->left = deleteNode(r->left,key);
		}
	}

	// If the tree had only one node then return
	if (r == NULL)
	return r;

	// STEP 2: UPDATE HEIGHT OF THE CURRENT NODE
	r->height = 1 + maxValue(height(r->left),
						height(r->right));

	// STEP 3: GET THE BALANCE FACTOR OF THIS NODE (to
	// check whether this node became unbalanced)
	int balance = getBalance(r);

	// If this node becomes unbalanced, then there are 4 cases

	// Left Left Case
	if (balance > 1 && getBalance(r->left) >= 0)
		return rightRotate(r);

	// Left Right Case
	if (balance > 1 && getBalance(r->left) < 0)
	{
		r->left = leftRotate(r->left);
		return rightRotate(r);
	}

	// Right Right Case
	if (balance < -1 && getBalance(r->right) <= 0)
		return leftRotate(r);

	// Right Left Case
	if (balance < -1 && getBalance(r->right) > 0)
	{
		r->right = rightRotate(r->right);
		return leftRotate(r);
	}

	return r;
}

// A utility function to print printTree traversal of
// the tree.
// The function also prints height of every node
void printTree(struct Node *root)
{
	if(root != NULL)
	{
		printTree(root->left);
		printf("%d ", root->key);
		printTree(root->right);
	}
}

int main()
{
	struct Node *root = NULL;
	int num;

	while (scanf("%d", &num), num != 0)
	{
		root = insert(root, num);
	}

	printTree(root);
	if (root != NULL)
	{
		printf("\n%d %d\n", height(root) - 1, root->key);
	}

	while (scanf("%d", &num), num != 0)
	{
		if (searchTree(root, num) == 1)
		{
			// printf("Found node %d!\n", num);
			root = deleteNode(root, num);
			printTree(root);
			if (root != NULL)
			{
				printf("\n%d %d\n", height(root) - 1, root->key);
			}
		}
		else
		{
			// printf("Node %d not found!\n", num);
		}
	}

	return 0;
}
