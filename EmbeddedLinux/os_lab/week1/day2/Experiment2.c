/*
Author- Sanjay Chaurasia
Orgnization- CDAC
Designation- Project Engineer


Objective-  Buffered output behavior

Understand why printf() and write() behave differently.

*/

// Headers
#include<stdio.h>
#include<unistd.h>

// Main function
int main()
{
	printf("A\n");
	sleep(5);
	write(1,"B\n",2);
	
	return 0;
}
