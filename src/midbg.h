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
typedef struct midbg_session_str midbg_session;
typedef struct midbg_breakpoint_str midbg_breakpoint;
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
midbg_session * midbg_open_session(FILE *fcommand, FILE *freply, 
				   unsigned long filter);
void midbg_close_session(midbg_session * dbgSess);
AMVP_RESULT midbg_set_program_args(midbg_session *dbgSess, 
					char * const argv[]);

/*************************************************************************/
/* Log functions */
AMVP_RESULT midbg_log(midbg_session *dbgSess, const char *format, ...);
char * midbg_get_log(midbg_session *dbgSess);

/*************************************************************************/
/* Program variable functions */
AMVP_RESULT midbg_get_scalar(midbg_session *dbgSess, const char *var, 
			     size_t size, unsigned long *val);
/* copy from one memory location to another */
AMVP_RESULT midbg_copy_bytes(midbg_session *dbgSess, const char *src_var,
				 const char *target_var, size_t size);
/* fetch some bytes */
AMVP_RESULT
midbg_get_bytes(midbg_session *dbgSess, const char *var1,
                unsigned char *buf, size_t size);
/* modify some bytes */
AMVP_RESULT midbg_put_bytes(midbg_session *dbgSess, const char *var1,
                const unsigned char *buf, size_t size);

/*************************************************************************/
/* breakpoint functions */
midbg_breakpoint * midbg_new_breakpoint(const char *label, int number,
					midbg_callback callback, void *args);
void midbg_free_breakpoint(midbg_breakpoint *breakpoint);
AMVP_RESULT midbg_add_breakpoint(midbg_session *dbgSess, char *command, 
		    const char *arg, const char *label, 
		    midbg_callback callback, void *args);
AMVP_RESULT midbg_delete_breakpoint(midbg_session *dbgSess,
				    midbg_breakpoint *breakpoint);
/* return the breakpoint structure with the given number */
midbg_breakpoint * midbg_find_breakpoint(midbg_session *dbgSess, 
					 int break_number);
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
/* execute a synchronized stepping. If we stop outside the step operation,
 * then we will return an error, valid values are for type are:
 *     next
 *     step
 *     finish
 *     next-instruction
 *     step-instruction
 */
AMVP_RESULT midbg_synch_step(midbg_session *dbgSess, char *type, char **results);
    
#ifdef __cplusplus
}
#endif
#endif
