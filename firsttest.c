#include "types.h"
#include "user.h"

//first testcode
// you must show different VM space among processes
int main(){
	int pid = fork();
	if (pid == 0) {
		// child
		printf(1, "Child current pid: %d\n", getpid());
		pvminfo();
	} else {
		// parent
		printf(1, "Parent current pid: %d\n", getpid());
		pvminfo();
		wait();
	}
	exit(); // process 종료 시스템콜
}
