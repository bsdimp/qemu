/* Taken from v7 signal.h from TUHS */

#define TARGET_NSIG 17

#define TARGET_SIGHUP	1	/* hangup */
#define TARGET_SIGINT	2	/* interrupt */
#define TARGET_SIGQUIT	3	/* quit */
#define TARGET_SIGILL	4	/* illegal instruction (not reset when caught) */
#define TARGET_SIGTRAP	5	/* trace trap (not reset when caught) */
#define TARGET_SIGIOT	6	/* IOT instruction */
#define TARGET_SIGEMT	7	/* EMT instruction */
#define TARGET_SIGFPE	8	/* floating point exception */
#define TARGET_SIGKILL	9	/* kill (cannot be caught or ignored) */
#define TARGET_SIGBUS	10	/* bus error */
#define TARGET_SIGSEGV	11	/* segmentation violation */
#define TARGET_SIGSYS	12	/* bad argument to system call */
#define TARGET_SIGPIPE	13	/* write on a pipe with no one to read it */
#define TARGET_SIGALRM	14	/* alarm clock */
#define TARGET_SIGTERM	15	/* software termination signal from kill */

/*  int	(*signal())(); */
#define TARGET_SIG_DFL	(int (*)())0
#define TARGET_SIG_IGN	(int (*)())1

#include "errno_defs.h"
#include "syscall_nr.h"
