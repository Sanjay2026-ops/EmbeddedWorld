/*
Author- Sanjay Chaurasia
Orgnization- CDAC
Designation- Project Engineer

Experiment 3 — Observe sleep() as blocking behavior
Objective- 

See that the process is alive but not running on CPU continuously.

*/

// Headers
#include<stdio.h>
#include<unistd.h>

// Main function
int main()
{
	printf("PID:  %d",getpid());
	printf("Going to sleep for 20 seconds...\n");
	sleep(20);
	printf("Woke up and exiting.\n");
	
	return 0;
}
