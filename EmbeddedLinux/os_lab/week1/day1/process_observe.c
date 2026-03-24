/*
Author- Sanjay chaurasia
Designation- Project Engineer
Orgnization- CDAC

*/

// Headers
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

// Global Variables
int var=100;

// called function
void sample_function()
{
	// Empty function just to print its address
}

// Main function
int main()
{
	int a=200;
	int *b=(int*)malloc(sizeof(int));
	
	if(b==NULL)
	{
		perror("Memory is dangling");
		return 1;
	}
	
	*b=300;
	
	printf("=======Process observation program=====\n");
	printf("PID : %d\n",getpid());
	printf("PPID : %d\n",getppid());
	
	printf("\n==========Address =======\n");
	printf("Address of global variable(var)  : %p\n",(void *)&var);
	printf("Address of local variable(a)  : %p\n",(void *)&a);
	printf("Address of dynamic variable(b)  : %p\n",(void *)&b);
	printf("Address of dynamic points to  : %p\n",(void *)b);
	printf("Address of sample function  : %p\n",(void *)sample_function);
	
	printf("\nProgram will sleep for 60 seconds. \n");
	printf("Use this this time to inspects me from another terminal.\n");
	
	sleep(60);
	
	free(b);  // // memory should be free if allocated
	printf("Existing. \n");
	
	return 0;
		
}







