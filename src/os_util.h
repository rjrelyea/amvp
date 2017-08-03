/*
 *  Linux utilities to executing test programs both under the debugger
 *  and outside of it.
 */

#include "amvp.h"
#include "midbg.h"
#ifndef os_util_h
#define os_util_h

#ifdef __cplusplus
extern "C"
{
#endif

typedef AMVP_RESULT (*amvpu_setup_callback)(midbg_session *);

/*
 * read everything from a file descriptor into newly allocated memory and
 * return it.
 */
char * amvpu_readalloc(int fd);

/* remove a directory and all it's contents */
int amvpu_rmdir_r(const char *path);

/* copy a file from source to dest. both source and dest should be paths
 * to regular files. Dest will be truncated if it exists and created if it
 * doesn't */
AMVP_RESULT amvpu_copyfile(char *src,char *dest);


/*
 * run the external text program. All the output from standard error and 
 * standard out are saved in a log which is returned. The caller is 
 * responsible for freeing that collected log.
 */
char *amvpu_exec_log(const char *client, const char *prog, 
	      char *const argv[], AMVP_RESULT *status);

/*
 * run the external test program under the debugger. All the output from 
 * standard error and standard out are saved in a log which is returned.
 * The caller is responsible for freeing that collected log. The debugger
 * session is controlled with the mi command interface for gdb using the
 * midbg library included in libamvp.a. Before the program gets launched,
 * 'callback' is called with a pointer to the midbg_session so that break
 * points and enviroment stuff can be set up. debugging control happens
 * through callbacks from the various breakpoint functions. Filter controls
 * what kinds of records are returned in the log. filter == 0 returns everything
 */
char *amvpu_exec_debug(const char *client, const char *prog, 
			char *const argv[], AMVP_RESULT *status,
			amvpu_setup_callback callback, unsigned long filter);
#ifdef __cplusplus
}
#endif
#endif
