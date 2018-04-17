/** @file
 * This is the public header file to be included by applications
 * using the midbg library.
 */

/*
 * debug api tools
 */

#ifndef midbg_h
#define midbg_h

#ifdef __cplusplus
extern "C"
{
#endif

/* structs and defines */
/*! @struct midbg_session
 *  @brief handle to the current debugging session.
 */
typedef struct midbg_session_str midbg_session;
/*! @struct midbg_breakpoint
 *  @brief handle to the current breakpoint
 */
typedef struct midbg_breakpoint_str midbg_breakpoint;

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
typedef AMVP_RESULT (*midbg_callback) 
   (midbg_session *sess,midbg_breakpoint *bkpt, const char *async, void *arg);
#define MAX_INPUT_LINE 4096
/* result class values */
#define DBG_DONE         "done"
#define DBG_RUNNING      "running"
#define DBG_CONNECTED    "connected"
#define DBG_ERROR        "error"
#define DBG_EXIT         "exit"
#define DBG_STOPPED      "stopped"
#define DBG_DISAPPEARED  "disappeared"
/* output types */
#define DBG_EXEC_ASYNC   '*'
#define DBG_REPLY        '^'
#define DBG_POSSIBLE_PROMPT '('
#define DBG_COMMAND      '-'
#define DBG_TOOLKIT      '#'
#define DBG_INFO         '='

#define DBG_EXEC_ASYNC_FLAG 0x000000000000001UL
#define DBG_REPLY_FLAG      0x000000000000002UL
#define DBG_PROMPT_FLAG     0x000000000000004UL
#define DBG_INFO_FLAG       0x000000000000008UL
#define DBG_COMMAND_FLAG    0x000000000000010UL
#define DBG_ASYNC_FLAG      0x000000000000020UL
#define DBG_APP_DATA_FLAG   0x000000000000040UL
#define DBG_TOOLKIT_FLAG    0x000000000000080UL

/*************************************************************************/
/* utilities to operate on reply strings */
int midbg_is_opening_bracket(char b);
char midbg_get_closing_bracket(char b);
/* If we are a list, a tuple, or a string, strip out contining string */
char * midbg_strip_bracket(const char *cp);
/* get a variable from a reply string. returned space must be freed by the
 * caller. For lists, tuples or strings, the controlling brackets are
 * included. Use 'midbg_strip_bracket' to remove them. */
char * midbg_get_var(const char *reply_string, const char *var);
/* same as midbg_get_var except we strip the controlling quotes,
 * will return an error for lists and tuples. caller must free
 * the space */
char * midbg_get_var_value(const char *reply_string, const char *var);

/*************************************************************************/
/* debug session functions */
/*! @brief midbg_open_session() Create a new debugging session. Session is 
           freed by midbg_close_session(). This function is used by 
           amvpu_exec_debug(). Test appplications need not call it.

   @param fcommand - stdio file descriptor to the command pipe
   @param freply - stdio file descriptor to the reply pipe
   @param filter - controls what kinds of records returned on the reply pipe.
          valid values are:
	DBG_EXEC_ASYNC_FLAG debugger asynchronous execution event
	DBG_REPLY_FLAG      debugger replies
	DBG_PROMPT_FLAG     debugger prompts
	DBG_INFO_FLAG       debugger info
	DBG_COMMAND_FLAG    commands to debugger
        DBG_APP_DATA_FLAG   data from the test program.
        DBG_TOOLKIT_FLAG    toolkit records
   @return midbg_session *
 */
midbg_session * midbg_open_session(FILE *fcommand, FILE *freply, 
				   unsigned long filter);
/*! @brief midbg_open_session() Close down a debug session and free it.
           This function is used by amvpu_exec_debug(). Test appplications 
           need not call it.

   @param dbgSess - session to close now.
*/
void midbg_close_session(midbg_session * dbgSess);
/*! @brief midbg_set_program_args() Set the args to be used by the program
           under test.  This function is used by amvpu_exec_debug(). Test 
           appplications need not call it.

   @param dbgSess - currrent debug session
   @param argv - null terminated array of arguments
   @return AMVP_RESULT
*/
AMVP_RESULT midbg_set_program_args(midbg_session *dbgSess, 
					char * const argv[]);

/*************************************************************************/
/* Log functions */
/*! @brief midbg_log() Append a string to the log.

   @param dbgSess - currrent debug session
   @param format - printf style format... 
   @return AMVP_RESULT
*/
AMVP_RESULT midbg_log(midbg_session *dbgSess, const char *format, ...);
/*! @brief midbg_get_log() Return a copy of the current log

   @param dbgSess - currrent debug session
   @return char *
*/
char * midbg_get_log(midbg_session *dbgSess);

/*************************************************************************/
/* Program variable functions */
/*! @brief midbg_get_scalar() Lookup a scalar variable in the debugger and 
              return it. 

   @param dbgSess - currrent debug session
   @param var - name of the variable
   @param size - size in bytes of variable (must be less than sizeof(unsigned long))
   @param val - pointer to unsigned long to accept the value of the variable.
   @return AMVP_RESULT
*/
AMVP_RESULT midbg_get_scalar(midbg_session *dbgSess, const char *var, 
			     size_t size, unsigned long *val);
/*! @brief midbg_copy_bytes() copy from one memory location to another 

   @param dbgSess - currrent debug session
   @param src_var - name of the variable or memory location to copy from.
   @param target_var - name of the variable or memory location to copy to.
   @param size - size in bytes to copy.
   @return AMVP_RESULT
*/
AMVP_RESULT midbg_copy_bytes(midbg_session *dbgSess, const char *src_var,
				 const char *target_var, size_t size);
/*! @brief midbg_get_bytes() fetch some bytes from memory or a variable

   @param dbgSess - currrent debug session
   @param var - name of the variable or memory location to copy from.
   @param buf - buffer to accept the bytes.
   @param size - size in bytes to copy.
   @return AMVP_RESULT
*/
AMVP_RESULT
midbg_get_bytes(midbg_session *dbgSess, const char *var,
                unsigned char *buf, size_t size);
/*! @brief midbg_get_bytes() write some bytes to memory or a variable

   @param dbgSess - currrent debug session
   @param var - name of the variable or memory location to copy to.
   @param buf - buffer with bytes to write.
   @param size - size in bytes to copy.
   @return AMVP_RESULT
*/
AMVP_RESULT midbg_put_bytes(midbg_session *dbgSess, const char *var,
                const unsigned char *buf, size_t size);

/*************************************************************************/
/* breakpoint functions */
midbg_breakpoint * midbg_new_breakpoint(const char *label, int number,
					midbg_callback callback, void *args);
void midbg_free_breakpoint(midbg_breakpoint *breakpoint);
/*! @brief midbg_add_breakpoint() Create a new breakpoint. When the breakpoint
            is called, callback is called with args.

   @param dbgSess - currrent debug session
   @param command - type of breakpoint. Valid commands are:
           "break-insert" - break at a location, arg = function or address.
	   "break-watch" - break on a reference, arg = variable or address.
           "catch-load"- break when a shared library is loaded, arg = library. 
           "catch-unload" - break when a shared library is unloaded, arg = library.
                   
   @param arg - string argument for the break command.
   @param label - Friendly label your breakpoint handler can use to identify this breakpoint, and to look up the breakpoint
   @param callback - function to handle your breakpoint. It will get the 
                     dbgSess, breakpoint, and args).
   @param args - arguement passed to the breakpoint handler.
   @return AMVP_RESULT
*/
AMVP_RESULT midbg_add_breakpoint(midbg_session *dbgSess, char *command, 
		    const char *arg, const char *label, 
		    midbg_callback callback, void *args);

/*! @brief midbg_delete_breakpoint() Delete a breakpoint.

   @param dbgSess - currrent debug session.
   @param breakpoint - breakpoint to be deleted.
   @return AMVP_RESULT
*/
AMVP_RESULT midbg_delete_breakpoint(midbg_session *dbgSess,
				    midbg_breakpoint *breakpoint);
/*! @brief midbg_delete_breakpoint() return the breakpoint structure 
              with the given number 

   @param dbgSess - currrent debug session.
   @param break_number - breakpoint number of the required breakpoint.
   @return AMVP_RESULT
*/
midbg_breakpoint * midbg_find_breakpoint(midbg_session *dbgSess, 
					 int break_number);
/*! @brief midbg_clear_all_breakpoints() Delete all the existing breakpoints

   @param dbgSess - currrent debug session.
   @return AMVP_RESULT
*/
AMVP_RESULT midbg_clear_all_breakpoints(midbg_session *dbgSess);

/* find the breakpoint associated with the reply and execute the breakpoint
 * callback. If successful, continue */
AMVP_RESULT midbg_handle_breakpoint(midbg_session *dbgSess,
				    const char *bkno_string,
				    const char *replybuf);

/*************************************************************************/
/* execution control functions */
/* run the program */
AMVP_RESULT midbg_run_test(midbg_session *dbgSess);
/*! @brief midbg_synch_step() execute a synchronized stepping. If we stop 
    outside the step operation, then we will return an error.

   @param dbgSess - currrent debug session.
   @param type - type of set. Valid types are:
      "next" - go to the next line in the program.
      "step" - go to the next line. If the current line is a call step into the function.
      "finish" - go to the end of the current function.
      "next-instruction" - go to the next instruction.
      "step-instruction" - go to the next instruction. If the current line is a call step into the function."
   @return AMVP_RESULT
*/
AMVP_RESULT midbg_synch_step(midbg_session *dbgSess, char *type, char **results);
    
#ifdef __cplusplus
}
#endif
#endif
