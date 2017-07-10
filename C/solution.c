#include <stdio.h>
int solution(int N){
	int tmp;
	static int i;
	static int flag;
	static int cur;
	static int cur_bf;
	tmp = N % 2;
	printf("%d\n", tmp);
	if(tmp == 0 && flag == 1){
		i++;
		//printf("i=%d\n", i);
	}
	if(tmp == 1 ){
		
		cur = i;
		if(cur > cur_bf)
			cur_bf = cur;
		i = 0;
		flag = 1;
		
	
	}
	if(N == 1){
			return cur_bf;
	}
	solution(N / 2);


}
int main(){
	int rval;
	rval = solution(8);
	printf("the rval is %d\n",rval);
	return 0;
	

}
