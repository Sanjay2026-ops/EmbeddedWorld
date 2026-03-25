/*
Author: Sanjay chaurasia
Orgnization: CDAC
Designation: Project Engineer


Objective- Observe the difference between

1.	library function: printf()
2.	system call related function: write()
*/


// Headers 
#include<stdio.h>
#include<unistd.h>
#include<string.h>

// Main function
int main()
{
	printf("Hello from printf\n");
	
	const char *msg="Hello from write\n";
	write(1,msg,strlen(msg));
	
	return 0;
}


