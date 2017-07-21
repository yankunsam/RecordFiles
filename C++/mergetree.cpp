#include <iostream>
#include <stack>
using namespace std;
struct TreeNode{
	int val;
	struct TreeNode *left;
	struct TreeNode *right;


};
TreeNode* mergeTrees(TreeNode* t1, TreeNode* t2) {
	if(t2==NULL) return t1;
	if(t1==NULL) return t2;
	
	TreeNode* res=t1;
	stack<TreeNode*> s1, s2;
	s1.push(t1), s2.push(t2);

	while( !s1.empty() ) {
		TreeNode* c1=s1.top();
		TreeNode* c2=s2.top();
		cout << "c1->val:" << c1->val << endl;
		cout << '\n' << endl;
		cout << "c2->val:" << c2->val << endl;
		s1.pop(), s2.pop();
		c1->val += c2->val;
		if( c1->right == NULL && c2->right != NULL)
			c1->right = c2->right;
		else if(c1->right != NULL && c2->right != NULL)
			s1.push(c1->right);
		s2.push(c2->right);
		if(c1->left == NULL&& c2->left != NULL)
			c1->left=c2->left;
		else if(c1->left != NULL && c2->left != NULL)
			s1.push(c1->left);
		s2.push(c2->left);

	}
	return res;

}
int main()
{
	TreeNode t1;
	t1.val = 100;
	t1.left = NULL;
	t1.right = NULL;

	TreeNode t2;
	t2.val = 200;
	t2.left = NULL;
	t2.right = NULL;
	TreeNode *t;
	t = mergeTrees(&t1,&t2);
	cout << t->val << endl;
	cout << '\n' << endl;



}
