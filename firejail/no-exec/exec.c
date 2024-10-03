#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
	char *newargv[] = { "/bin/ls", "/", NULL };
	char *newenviron[] = { NULL };

	execve("/bin/ls", newargv, newenviron);
	perror("execve");   /* execve() returns only on error */
	exit(EXIT_FAILURE);
}
