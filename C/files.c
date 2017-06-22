#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main()
{
	int i = 0;
	int fd = 0;
	for(i=0;;i++){
		fd = open("./test",O_RDWR | O_CREAT);
		if(fd < 0){

			perror("open:");
			break;
		}
	}
	printf("The limits of files that a process can open is %d\n",i);
	return 0;



}
