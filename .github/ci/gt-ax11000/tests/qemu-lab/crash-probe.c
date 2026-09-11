#include <signal.h>
/* A negative control for the harness, never part of firmware. */
int main(void) { raise(SIGSEGV); return 99; }
