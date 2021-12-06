#include "types.h"
#include "user.h"

// in second testcode, you must show the increase of usage of VM space
// If you don't know how to use that API, refer to other test code like "init.c", "usertest.c"
int main(){
  printf(1, "initial state of VM of this process\n");
  printf(1, "current pid: %d\n", getpid());
  pvminfo();
  printf(1, "\n");
  printf(1, "after allocating page\n");
  printf(1, "current pid: %d\n", getpid());
  malloc(4096*15);
  pvminfo();
	exit();
}
