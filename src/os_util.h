/** @file
 *  This is the public header file to be included by applications
 *  using the libamvp utilities to executing test programs both under 
 *  the debugger and outside of it.
 */

#include "amvp.h"
#include "midbg.h"
#ifndef os_util_h
#define os_util_h

#ifdef __cplusplus
extern "C"
{
#endif

/*! @brief amvpu_setup_callback() callback from  amvpu_exec_debug(). 
            See amvpu_exec_debug() for more information.

   @param midbg_session Pointer to the debug context
   @return AMVP_RESULT
 */

typedef AMVP_RESULT (*amvpu_setup_callback)(midbg_session *);

/*! @brief amvpu_readalloc() read everything from a file descriptor into 
     newly allocated memory and return it. Caller is responsible for freeing
     the result.

   @param fd open file descriptor
   @return char *
 */
char * amvpu_readalloc(int fd);

/*! @brief amvpu_rmdir_r() remove a directory and all it's contents

   @param path - path to the directory to remove
   @return int
 */
int amvpu_rmdir_r(const char *path);

/*! @brief amvpu_copyfile() copy a file from source to dest. both source 
          and dest should be paths to regular files. Dest will be truncated 
          if it exists and created if it doesn't

   @param src - path to the source file
   @param dest - path to the destination file
   @return AMVP_RESULT
 */
AMVP_RESULT amvpu_copyfile(char *src,char *dest);


/*! @brief amvpu_exec_log() run the external text program. All the output 
            from standard error and standard out are saved in a log which 
            is returned. The caller is responsible for freeing that collected 
            log.

   @param client - name of the client under test, used to create unique temp files
   @param prog - path to program
   @param argv - null terminated array of arguments for the program
   @param status - pointer to an AMVP_RESULT to return the result of the test
   @return char * (returned log)
 */
char *amvpu_exec_log(const char *client, const char *prog, 
	      char *const argv[], AMVP_RESULT *status);

/*! @brief amvpu_exec_debug() Run the external test program under the 
            debugger. All the output from standard error and standard out are 
	    saved in a log which is returned.  The caller is responsible for 
            freeing that collected log. The debugger session is controlled 
            with the mi command interface for gdb using the midbg library 
            included in libamvp.a. Before the program gets launched,
            'callback' is called with a pointer to the midbg_session so that 
            break points and enviroment stuff can be set up. debugging control 
            happens through callbacks from the various breakpoint functions. 

   @param client - name of the client under test, used to create unique temp files
   @param prog - path to program
   @param argv - null terminated array of arguments for the program
   @param status - pointer to an AMVP_RESULT to return the result of the test
   @param callback - call back called before program exec to setup the debugger
   @param filter - controls what kinds of records are returned in the log. 
            filter == 0 returns everything. See midbg_open_session().
   @return char * (returned log)
 */
char *amvpu_exec_debug(const char *client, const char *prog, 
			char *const argv[], AMVP_RESULT *status,
			amvpu_setup_callback callback, unsigned long filter);
#ifdef __cplusplus
}
#endif
#endif
