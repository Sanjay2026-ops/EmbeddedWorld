/*
Author- Sanjay
Orgnization- CDAC
Designation- Project Engineer


Problem:

1.	print PID
2.	print one line using printf
3.	print one line using write
4.	sleep for 10 seconds
5.	exit



*/



#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main()
{
    int pid = getpid();

    // Print PID
    printf("PID: %d\n", pid);

    // Print one line using printf
    printf("This line is printed using printf.\n");

    // Print one line using write
    const char *msg = "This line is printed using write.\n";
    write(1, msg, strlen(msg));

    // Sleep for 10 seconds
    sleep(10);

    // Exit
    return 0;
}
