#include <stdio.h>
#include <stdlib.h>
struct listNode {
	int val;
	struct listNode *next;
};
#if 1
struct listNode *reverse(struct listNode *head, int m ,int n){
	int tmp;
	struct listNode *head_ori;
	head_ori = malloc(sizeof(*head));
	struct listNode *p,*q,*cur;
	struct listNode *p_pri, *q_pri, *q_post;
	int i;
	/*todo if(head) == NULL*/
	head_ori->next = head;

	if( m==n ){
		printf("m=%d n=%d,so there is no need to reverse\n",m,n);
		return head;
	}
	if(m > n){
		return head_ori->next;
	
	}
	cur = head;
	/*find the element m/n*/
	for( i = 1; i <=n && cur != NULL; i++ ){
		if( i == m){
			p = cur;
			printf("val_m:%d\n",p->val);
		}
		if(i == n){
			q = cur;
			q_post = q->next;
			printf("val_n:%d\n",q->val);
			break;
		}
		if( m != 1 && i < m)
			p_pri = cur;
		if(m == 1)
			p_pri = head_ori;
		q_pri = cur;
		cur = cur->next;
			
	}
	if( p == NULL || q == NULL ){
		printf("Maybe you give the wrong m/n\n");
		return NULL;
	}
	/*reverse*/
	p_pri->next = q;
	q_pri->next = p;
	q->next = p->next;
	p->next = q_post;

	return head_ori->next;

}
#endif
int main(){
        struct listNode *p;	
	struct listNode list_0;
	list_0.val = 11;
	struct listNode list_1;
	list_1.val = 22;
	struct listNode list_2;
	list_2.val = 33;
	list_0.next = &list_1;
	list_1.next = &list_2;
	list_2.next = NULL;
	p = reverse(&list_0,1,3);
	printf("%d\n", p->val);
	printf("%d\n", p->next->val);
	printf("%d\n", p->next->next->val);
	


}
