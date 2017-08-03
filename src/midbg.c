/*
 * debug api tools
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "amvp.h"
#include "midbg.h"

struct midbg_session_str {
    FILE *fcommand;
    FILE *freply;
    char *log;
    unsigned long filter;
    unsigned long record_type;
    int new_line;
    midbg_breakpoint *break_points;
    midbg_breakpoint *last_break_point;
};
struct midbg_breakpoint_str {
    midbg_breakpoint *next;
    const char *label;
    int break_number;
    midbg_callback break_callback;
    void   *user_args;
};

static char *
append_buffer(char *buf, const char *new) {
    int newlen = new ? strlen(new): 0;
    int buflen = buf ? strlen(buf) : 0;
    char *newbuf = realloc(buf, newlen +buflen +1);

    if (newbuf == NULL) {
	free(buf);
	return NULL;
    }
    memcpy(&newbuf[buflen],new ? new : "", newlen+1);
    return newbuf;
}

/* is a character an token to indicate tuple, list, or string? */
int 
midbg_is_opening_bracket(char b)
{
   switch (b) {
   case '{':
   case '[':
   case '"':
	return 1;
   }
   return 0;
}

/* find the terminating character for a tuple, list, or string */
char 
midbg_get_closing_bracket(char b)
{
   switch (b) {
   case '{' : return '}';
   case '[' : return ']';
   case '"' : return '"';
   }
   return 0;
}

/* skip to the end of this list, tuple, or string. if cp
 * is not a list, tuple, or string, skip to the end */
static const char *
skip_bracket(const char *cp)
{
    char open = *cp;
    char close = midbg_get_closing_bracket(open);

    for (cp++; *cp; cp++) {
	if (*cp == close) {
	    return cp;
	}
	if (open == '"') {
	    continue;
	}
	if ((*cp == '=') && (midbg_is_opening_bracket(*(cp+1)))) {
	    cp = skip_bracket(cp+1);
	}
    }
    return cp-1; /* back up to before the NULL */
}

/* find the next variable.*/
static const char *
next_var(const char *cp)
{
    for (;*cp; cp++) {
	switch (*cp) {
	case ',':
	    return cp+1;
	case '=':
	    if (midbg_is_opening_bracket(*(cp+1))) {
		cp = skip_bracket(cp+1);
	    }
	    break;
	default:
	    break;
	}
    }
    return cp;
}

static char *
fetch_var(const char *cp)
{
    const char *end = next_var(cp);
    const char *start = cp+1; /* drop the = sign */
    int len = end - start;   
    char *new = malloc(len);
    memcpy(new,start,len);
    new[len-1] = 0;
    return new;
}

/* If we are a list, a tuple, or a string, strip out contining string */
char *
midbg_strip_bracket(const char *cp)
{
    if (midbg_is_opening_bracket(*cp)) {
	int len = strlen(cp);
	char *new;
	if (midbg_get_closing_bracket(*cp) != cp[len-1]) {
	    /*malformed, no closing bracket, return to the end */
	    len++;
	}
	new  = malloc(len-1);
	memcpy(new,cp+1,len-2);
	new[len-2] = 0;
	return new;
    }
    return strdup(cp);
}

/* get a variable from a reply string. returned space must be freed by the
 * caller. for Lists, tuples or strings, the controlling brackets are
 * included. Use 'midbg_strip_bracket' to remove them. */
char *
midbg_get_var(const char *reply_string, const char *var)
{
   char * string = strdup(reply_string);
   char * new_string = strdup(reply_string);
   const char *next;
   const char *cp;
   int var_len;

   /* handle embedded variables */
   while ((next = strchr(var,'.')) != NULL) {
	char *sub_var = strdup(var);
	sub_var[next - var] = 0;
	new_string = midbg_get_var(string, sub_var);
	free(string);
	free(sub_var);
	if (new_string == NULL) {
	    return NULL;
	}
	/* variable doesn't have any additional results */
	if (*new_string == '"') {
	    free(new_string);
	    return NULL;
	}
	string = midbg_strip_bracket(new_string);
	free(new_string);
        var = next+1;
    }
    var_len = strlen(var);
    for (cp = string; *cp; cp = next_var(cp)) {
	if (strncmp(cp, var, var_len) == 0) {
	    if (cp[var_len] != '=') {
		free(string);
		return NULL;
	    }
	    new_string = fetch_var(cp+var_len);
	    free(string);
	    return new_string;
	}
    }
    free(string);
    return NULL;
}

char *
midbg_get_var_value(const char *reply_string, const char *var)
{
    char *string = midbg_get_var(reply_string, var);
    char *new_string;
    if (*string != '"') {
	free(string);
	return NULL;
    }
    new_string = midbg_strip_bracket(string);
    free(string);
    return new_string;
}

midbg_session *
midbg_open_session(FILE *fcommand, FILE *freply, unsigned long filter)
{
    midbg_session * dbgSess;

    dbgSess = malloc(sizeof(midbg_session));
    dbgSess->log = NULL;
    dbgSess->break_points = NULL;
    dbgSess->last_break_point = NULL;
    dbgSess->fcommand = fcommand;
    dbgSess->freply = freply;
    dbgSess->record_type = DBG_APP_DATA_FLAG;
    dbgSess->filter = filter;
    dbgSess->new_line = 1;
    return dbgSess;
}

void
midbg_close_session(midbg_session * dbgSess)
{
    midbg_breakpoint *this;
    midbg_breakpoint *next;

    free(dbgSess->log);
    for (this = dbgSess->break_points; this; this=next) {
	next = this->next;
	midbg_free_breakpoint(this);
    }
    fclose(dbgSess->fcommand);
    fclose(dbgSess->freply);
    free(dbgSess);
    dbgSess->log = NULL;
    dbgSess->break_points = NULL;
    dbgSess->last_break_point = NULL;
}

midbg_breakpoint *
midbg_new_breakpoint(const char *label, int number,
					midbg_callback callback, void *args)
{
   midbg_breakpoint *breakpoint;

   breakpoint = malloc(sizeof(midbg_breakpoint));
   breakpoint->next = NULL;
   breakpoint->label = label;
   breakpoint->break_number = number;
   breakpoint->break_callback = callback; 
   breakpoint->user_args = args; 
   return breakpoint;
}

void
midbg_free_breakpoint(midbg_breakpoint *breakpoint)
{
    free(breakpoint);
}

#define DBG_PROMPT "(gdb)"

static unsigned long
midbg_get_record_type(const char *string) 
{
    switch(string[0]) {
    case DBG_EXEC_ASYNC:
	return DBG_EXEC_ASYNC_FLAG;
    case DBG_REPLY:
	return DBG_REPLY_FLAG;
    case DBG_COMMAND:
	return DBG_COMMAND_FLAG;
    case DBG_INFO:
	return DBG_INFO_FLAG;
    case DBG_TOOLKIT:
	return DBG_TOOLKIT_FLAG;
    case DBG_POSSIBLE_PROMPT:
	if (strncmp(string, DBG_PROMPT, sizeof(DBG_PROMPT)-1) == 0) {
	    return DBG_PROMPT_FLAG;
	}
	break;
    default:
	break;
     }
     return DBG_APP_DATA_FLAG;
}

AMVP_RESULT
midbg_log(midbg_session *dbgSess, const char *format, ...)
{
   va_list arguments;
   char outbuf[MAX_INPUT_LINE];
   int len = strlen(format);
   int newline = (len && (format[len-1] == '\n'));

   if (dbgSess->new_line) {
	dbgSess->record_type = midbg_get_record_type(format);
   }
   dbgSess->new_line = newline;

   /* skip the records we requested */
   if (dbgSess->record_type & dbgSess->filter) {
	return AMVP_SUCCESS;
   }

   va_start(arguments, format);
   vsnprintf(outbuf,MAX_INPUT_LINE-1, format, arguments);
   dbgSess->log = append_buffer(dbgSess->log,outbuf);

   va_end(arguments);
   if (dbgSess->log == NULL) {
	return AMVP_MALLOC_FAIL;
   }
   return AMVP_SUCCESS;
}

char *
midbg_get_log(midbg_session *dbgSess)
{
    if (dbgSess->log == NULL) {
	return NULL;
    }
    return strdup(dbgSess->log);
}

AMVP_RESULT
midbg_add_breakpoint(midbg_session *dbgSess, char *command, 
		    const char *arg, const char *label, 
		    midbg_callback callback, void *args)
{
    char replybuf[MAX_INPUT_LINE];
    char *bkpt_number;
    int number;
    midbg_breakpoint *breakpoint;
    AMVP_RESULT rv;

    fprintf(dbgSess->fcommand,"-%s %s\n", command, arg);
    midbg_log(dbgSess,"-%s %s\n",command, arg);
    fflush(dbgSess->fcommand); /* make sure the command is sent */
    do {
	char *resp;
	resp = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (resp == NULL) {
	    return AMVP_DBG_ERR;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
    } while (replybuf[0] != DBG_REPLY);
    if (memcmp(&replybuf[1],DBG_DONE,sizeof(DBG_DONE)-1) != 0) {
	return AMVP_DBG_ERR;
    }
    bkpt_number = midbg_get_var_value(replybuf,"bkpt.number");
    if (bkpt_number == NULL) {
	midbg_log(dbgSess,
		 "#***Could not get bkpt.number variable from reply\n");
	return AMVP_DBG_PARSE_ERR;
    }
    number = atoi(bkpt_number);
    free(bkpt_number);
    breakpoint = midbg_new_breakpoint(label, number, callback, args);
    if (dbgSess->last_break_point == NULL) {
	dbgSess->break_points=breakpoint;
    } else {
	dbgSess->last_break_point->next = breakpoint;
    }
    dbgSess->last_break_point=breakpoint;
    return AMVP_SUCCESS;
}

static midbg_breakpoint * midbg_find_breakpoint_parent(
				midbg_session *dbgSess, midbg_breakpoint *bp);
static AMVP_RESULT
midbg_remove_breakpoint(midbg_session *dbgSess, midbg_breakpoint *bp)
{
    midbg_breakpoint *parent = NULL;
    if (dbgSess->break_points == bp) {
	dbgSess->break_points = bp->next;
    } else {
	parent = midbg_find_breakpoint_parent(dbgSess, bp);
	if (parent == NULL) {
	    return AMVP_DBG_UNKNOWN_BREAKPOINT;
	}
	parent->next = bp->next;
    }

    if (dbgSess->last_break_point == bp) {
	dbgSess->last_break_point = parent;
    }
    return AMVP_SUCCESS;
}

AMVP_RESULT
midbg_delete_breakpoint(midbg_session *dbgSess, midbg_breakpoint *bp)
{
    char replybuf[MAX_INPUT_LINE];
    int number = bp->break_number;
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* we need to do 3 things to delete a breakpoint, remove it from
     * the breakpoint list in the session, free it, and delete the
     * debugger instance. We attempt all three even if we have an
     * error in one of them. If anything fails we return an error the
     * the caller */
    rv = midbg_remove_breakpoint(dbgSess, bp);
    midbg_free_breakpoint(bp);

    fprintf(dbgSess->fcommand,"-break-delete %d\n", number);
    midbg_log(dbgSess,"-break-delete %d\n", number);
    fflush(dbgSess->fcommand); /* make sure the command is sent */
    do {
	char *resp;
	resp = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (resp == NULL) {
	    return AMVP_DBG_ERR;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
    } while (replybuf[0] != DBG_REPLY);
    if (memcmp(&replybuf[1],DBG_DONE,sizeof(DBG_DONE)-1) != 0) {
	return AMVP_DBG_ERR;
    }
    return rv;
}

/* return the breakpoint structure with the given number */
midbg_breakpoint *
midbg_find_breakpoint(midbg_session *dbgSess, int break_number)
{
    midbg_breakpoint *this;

    for (this=dbgSess->break_points; this; this=this->next) {
	if (this->break_number == break_number) {
	    return this;
	}
    }
    return NULL;
}

/* return the breakpoint structure with the given number */
AMVP_RESULT 
midbg_clear_all_breakpoints(midbg_session *dbgSess)
{
    AMVP_RESULT rv, rv1 = AMVP_SUCCESS;

    while (dbgSess->break_points) {
	rv = midbg_delete_breakpoint(dbgSess, dbgSess->break_points);
	/* remember an errors along the way and return the last one when
 	 * we return */
	if (rv != AMVP_SUCCESS) {
	    rv1 = rv;
	   /* keep going and try to delete the remaining break points */
	}
    }
    return rv1;
}

/* return the breakpoint structure with the given number */
static midbg_breakpoint *
midbg_find_breakpoint_parent(midbg_session *dbgSess, midbg_breakpoint *bp)
{
    midbg_breakpoint *this;

    for (this=dbgSess->break_points; this; this=this->next) {
	if (this->next == bp) {
	    return this;
	}
    }
    return NULL;
}


/* find the breakpoint associated with the reply and execute the breakpoint
 * callback. If successful, continue */
AMVP_RESULT 
midbg_handle_breakpoint(midbg_session *dbgSess, const char *break_number_string,
			const char *replybuf)
{
    char *bkptno = midbg_get_var_value(&replybuf[1],break_number_string);
    midbg_breakpoint *break_point;
    int break_number;
    AMVP_RESULT rv;

    if (bkptno == NULL) {
	return AMVP_DBG_PARSE_ERR;
    }
    break_number = atoi(bkptno);
    free(bkptno);
    break_point = midbg_find_breakpoint(dbgSess, break_number);
    if (break_point == NULL) {
	return AMVP_DBG_UNKNOWN_BREAKPOINT;
    }
    rv = midbg_log(dbgSess,"#");
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = midbg_log(dbgSess,break_point->label);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = midbg_log(dbgSess," called\n");
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = break_point->break_callback(dbgSess, break_point, replybuf, 
				     break_point->user_args);
    if (rv == AMVP_SUCCESS) {
	/* now that we've handled the breakpoint, continue */
	fprintf(dbgSess->fcommand,"-exec-continue\n");
        midbg_log(dbgSess,"-exec-continue\n");
	fflush(dbgSess->fcommand);
    }
    return rv;
}

AMVP_RESULT
midbg_synch_step(midbg_session *dbgSess, char *type, char **reply_return) 
{
    char replybuf[MAX_INPUT_LINE];
    char *reason;
    const char *expected_reason;
    AMVP_RESULT rv = AMVP_SUCCESS;

    if (reply_return) { *reply_return = NULL; }
    fprintf(dbgSess->fcommand,"-exec-%s\n",type);
    midbg_log(dbgSess,"-exec-%s\n",type);
    fflush(dbgSess->fcommand); /* make sure the command is sent */
    /* get the reply status */
    do {
	char *resp;
	resp = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (resp == NULL) {
	    return AMVP_DBG_ERR;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
    } while (replybuf[0] != DBG_REPLY);
    if (memcmp(&replybuf[1],DBG_RUNNING,sizeof(DBG_RUNNING)-1) != 0) {
	rv =AMVP_DBG_ERR;
	goto done;
    }
    /* wait for the stopped */
    do {
	char *resp;
	resp = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (resp == NULL) {
	    return AMVP_DBG_ERR;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
	if (replybuf[0] == DBG_EXEC_ASYNC) {
    	    if (memcmp(&replybuf[1],DBG_STOPPED,sizeof(DBG_STOPPED)-1) == 0) {
		break;
    	    }
	}
    } while (1);
    /* if we stop for any other reason than we completed the finish, throw
     * an error */
    reason = midbg_get_var_value(replybuf,"reason");
    if (reason == NULL) {
	rv = AMVP_DBG_PARSE_ERR;
	goto done;
    }
    expected_reason = strcmp(type,"finish") == 0 ? 
		"function-finished" : "end-stepping-range";
    if (strcmp(reason,expected_reason) != 0) {
	free(reason);
	rv = AMVP_DBG_ERR;
	goto done;
    }
    free(reason);

done:
    if (reply_return) {
	*reply_return = strdup(replybuf);
    }
    return rv;
}

AMVP_RESULT
midbg_set_program_args(midbg_session *dbgSess, char * const argv[]) 
{
    char replybuf[MAX_INPUT_LINE];
    int count;
    AMVP_RESULT rv;

    /* count the args */
    for (count = 0; argv[count]; count++) ;

    if (count <= 1) {
	return AMVP_SUCCESS;
    }

    fprintf(dbgSess->fcommand,"-exec-arguments");
    midbg_log(dbgSess,"-exec-arguments");
    for (count=1; argv[count]; count++) {
	fprintf(dbgSess->fcommand," %s",argv[count]);
        midbg_log(dbgSess," %s",argv[count]);
    }
    fprintf(dbgSess->fcommand,"\n");
    midbg_log(dbgSess,"\n");
    fflush(dbgSess->fcommand); /* make sure the command is sent */
    do {
	char *resp;
	resp = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (resp == NULL) {
	    return AMVP_DBG_ERR;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
    } while (replybuf[0] != DBG_REPLY);
    if (memcmp(&replybuf[1],DBG_DONE,sizeof(DBG_DONE)-1) != 0) {
	return AMVP_DBG_ERR;
    }
    return AMVP_SUCCESS;
}

AMVP_RESULT
midbg_set_output_flags(midbg_session *dbgSess, unsigned long filter) 
{
    dbgSess->filter = filter;
    return AMVP_SUCCESS;
}

AMVP_RESULT
midbg_get_scalar(midbg_session *dbgSess, const char *var, size_t size, unsigned long *val) 
{
    char replybuf[MAX_INPUT_LINE];
    char *varstr;
    AMVP_RESULT rv;

    fprintf(dbgSess->fcommand,"-data-evaluate-expression %s\n", var);
    midbg_log(dbgSess,"-data-evalute-expression %s\n", var);
    /*fprintf(dbgSess->fcommand,"-data-read-memory &%s u %ld 1 1\n", var, size);*/
    fflush(dbgSess->fcommand); /* make sure the command is sent */
    do {
	char *resp;
	resp = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (resp == NULL) {
	    return AMVP_DBG_ERR;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
    } while (replybuf[0] != DBG_REPLY);
    if (memcmp(&replybuf[1],DBG_DONE,sizeof(DBG_DONE)-1) != 0) {
	return AMVP_DBG_ERR;
    }
    varstr = midbg_get_var_value(replybuf,"value");
    if (varstr == NULL) {
	return AMVP_DBG_PARSE_ERR;
    }
    *val = atoi(varstr);
    free(varstr);
    return AMVP_SUCCESS;
}

AMVP_RESULT
midbg_copy_bytes(midbg_session *dbgSess, const char *var1, const char *var2, size_t size) 
{
    char replybuf[MAX_INPUT_LINE];
    char *varstr;
    AMVP_RESULT rv;

    fprintf(dbgSess->fcommand,"-data-read-memory-bytes %s %ld\n", var1, size);
    midbg_log(dbgSess,"-data-read-memory-bytes %s %ld\n", var1, size);
    fflush(dbgSess->fcommand); /* make sure the command is sent */
    do {
	char *resp;
	resp = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (resp == NULL) {
	    return AMVP_DBG_ERR;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
    } while (replybuf[0] != DBG_REPLY);
    if (memcmp(&replybuf[1],DBG_DONE,sizeof(DBG_DONE)-1) != 0) {
	return AMVP_DBG_ERR;
    }
    varstr = midbg_get_var(replybuf,"memory.contents");
    if (varstr == NULL) {
	return AMVP_DBG_PARSE_ERR;
    }
    fprintf(dbgSess->fcommand,"-data-write-memory-bytes %s %s\n", var2, varstr);
    midbg_log(dbgSess,"-data-write-memory-bytes %s %s\n", var2, varstr);
    fflush(dbgSess->fcommand); /* make sure the command is sent */
    free(varstr);
    do {
	char *resp;
	resp = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (resp == NULL) {
	    return AMVP_DBG_ERR;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
    } while (replybuf[0] != DBG_REPLY);
    if (memcmp(&replybuf[1],DBG_DONE,sizeof(DBG_DONE)-1) != 0) {
	return AMVP_DBG_ERR;
    }
    return AMVP_SUCCESS;
}

static unsigned char
from_hex(char c) 
{
   if ((c >= '0') && (c <= '9')) return c-'0';
   if ((c >= 'a') && (c <= 'f')) return c-'a'+0xa;
   if ((c >= 'A') && (c <= 'F')) return c-'A'+0xA;
   return 0x10;
}

static char
to_hex(unsigned char c) 
{
   if ((c >= 0) && (c <= 9)) return c+'0';
   return c+'a'-0xa;
}

AMVP_RESULT
midbg_get_bytes(midbg_session *dbgSess, const char *var, 
		unsigned char *buf, size_t size) 
{
    char replybuf[MAX_INPUT_LINE];
    char *varstr;
    AMVP_RESULT rv;
    int i;

    fprintf(dbgSess->fcommand,"-data-read-memory-bytes %s %ld\n", var, size);
    midbg_log(dbgSess,"-data-read-memory-bytes %s %ld\n", var, size);
    fflush(dbgSess->fcommand); /* make sure the command is sent */
    do {
	char *resp;
	resp = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (resp == NULL) {
	    return AMVP_DBG_ERR;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
    } while (replybuf[0] != DBG_REPLY);
    if (memcmp(&replybuf[1],DBG_DONE,sizeof(DBG_DONE)-1) != 0) {
	return AMVP_DBG_ERR;
    }
    varstr = midbg_get_var_value(replybuf,"memory.contents");
    if (varstr == NULL) {
	return AMVP_DBG_PARSE_ERR;
    }
    rv = AMVP_SUCCESS;
    for (i=0; i < size; i++) {
	unsigned char b1 = from_hex(varstr[i*2]);
	unsigned char b2;
	if (b1 > 0xf) {
	    rv = AMVP_DBG_PARSE_ERR;
	    break;
	}

	b2 = from_hex(varstr[i*2+1]);
	if (b2 > 0xf) {
	    rv = AMVP_DBG_PARSE_ERR;
	    break;
	}
	buf[i] = (b1 << 4) | b2;
    }
    free(varstr);
    return rv;
}

AMVP_RESULT
midbg_put_bytes(midbg_session *dbgSess, const char *var,
		const unsigned char *buf, size_t size) 
{
    char replybuf[MAX_INPUT_LINE];
    char *varstr;
    int i;
    AMVP_RESULT rv;

    varstr = malloc(size*2+1);
    for (i=0; i < size; i++) {
	varstr[2*i] = to_hex((buf[i] >> 4)&0xf);
	varstr[2*i+1] = to_hex(buf[i]&0xf);
    }
    varstr[2*i] = 0;

    fprintf(dbgSess->fcommand,"-data-write-memory-bytes %s \"%s\"\n", 
								var, varstr);
    midbg_log(dbgSess,"-data-write-memory-bytes %s \"%s\"\n", var, varstr);
    fflush(dbgSess->fcommand); /* make sure the command is sent */
    free(varstr);
    do {
	char *resp;
	resp = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (resp == NULL) {
	    return AMVP_DBG_ERR;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
    } while (replybuf[0] != DBG_REPLY);
    if (memcmp(&replybuf[1],DBG_DONE,sizeof(DBG_DONE)-1) != 0) {
	return AMVP_DBG_ERR;
    }
    return AMVP_SUCCESS;
}

AMVP_RESULT
midbg_traceback(midbg_session *dbgSess)
{
    char replybuf[MAX_INPUT_LINE];
    AMVP_RESULT rv;

    fprintf(dbgSess->fcommand,"-stack-list-frames\n");
    midbg_log(dbgSess,"-stack-list-frames\n");
    fflush(dbgSess->fcommand); /* make sure the command is sent */
    do {
	char *resp;
	resp = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (resp == NULL) {
	    return AMVP_DBG_ERR;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
    } while (replybuf[0] != DBG_REPLY);
    if (memcmp(&replybuf[1],DBG_DONE,sizeof(DBG_DONE)-1) != 0) {
	return AMVP_DBG_ERR;
    }
    return AMVP_SUCCESS;
}


AMVP_RESULT midbg_run_test(midbg_session *dbgSess) {
    char replybuf[MAX_INPUT_LINE];
    AMVP_RESULT rv = AMVP_SUCCESS;

    fprintf(dbgSess->fcommand,"-exec-run\n");
    midbg_log(dbgSess,"-exec-run\n");
    fflush(dbgSess->fcommand);
    do {
	char *rep;
	rep = fgets(replybuf,sizeof(replybuf),dbgSess->freply);
	if (rep == NULL) {
	    break;
	}
	rv = midbg_log(dbgSess,replybuf);
	if (rv != AMVP_SUCCESS) {
	    return rv;
	}
        /* detect errors */
	if (replybuf[0] == DBG_REPLY) {
	    if (memcmp(&replybuf[1],DBG_ERROR,sizeof(DBG_ERROR)-1) == 0) {
		rv = AMVP_DBG_ERR;
		break;
	    }
	}
	/* handle assync status */
	if (replybuf[0] == DBG_EXEC_ASYNC) {
	    /* NOTE: if we are stopped, then we either must do something to 
	     * keep going or we must terminate. Otherwise we will hang 
	     * forever */
	    if (memcmp(&replybuf[1],DBG_STOPPED,sizeof(DBG_STOPPED)-1) == 0) {
		char *reason = midbg_get_var_value(replybuf,"reason");
		if (reason == NULL) {
		    rv = AMVP_DBG_PARSE_ERR;
		    break;
		}
		if (strcmp(reason,"exited-normally") == 0) {
		    /* we've completed the program drop back to caller 
		     * with SUCCESS */
		    free(reason);
		    break;
		}
		if (strcmp(reason,"exited") == 0) {
		    /* program completed, but returned an error code, return 
		     * that to the caller */
		    char *exit_code_var 
				= midbg_get_var_value(replybuf,"exit-code");
		    int exit_code;
		    rv = AMVP_DBG_ERR;
		    if (exit_code_var && 
				((exit_code = atoi(exit_code_var)) != 0)) {
			rv = exit_code;
		    }
		    free(exit_code_var);
		    free(reason);
		    break;
		}
		if ((strcmp(reason,"breakpoint-hit") == 0) || /* breakpoint */
		    (strcmp(reason,"solib-event") == 0)) {    /* catchpoint */
		    free(reason);
		    rv = midbg_handle_breakpoint(dbgSess, "bkptno", replybuf);
		    if (rv != AMVP_SUCCESS) {
			break;
		    }
		} else if (strcmp(reason,"watchpoint-trigger") == 0) {
		    /* watchpoint */
		    rv = midbg_handle_breakpoint(dbgSess, "wpt.number", 
						 replybuf);
		    if (rv != AMVP_SUCCESS) {
			break;
		    }
		} else if (strcmp(reason,"watchpoint-scope") == 0) {
		    /* watchpoint */
		    rv = midbg_handle_breakpoint(dbgSess, "wpnum", replybuf);
		    if (rv != AMVP_SUCCESS) {
			break;
		    }
		} else {
		    /* unexpected program stoppage (crash or something). */
		    /* FUTURE handle "function-finished" for exec-finish. */
		    /* FUTURE handle "end-stepping-range" for stepping 
		     *  functions. */
		    /* FUTURE handle "exit-signalled" for signalling. */
		    /* FUTURE handle "location-reached" for until operations. */
		   (void) midbg_traceback(dbgSess);
		   free(reason);
		   rv = AMVP_DBG_ERR;
		   break;
		}
	    } else if (memcmp(&replybuf+1,DBG_DISAPPEARED,
					sizeof(DBG_DISAPPEARED)-1) == 0) {
		rv = AMVP_DBG_ERR;
		break;
	    }
	}
    } while (1);
    return rv;
}
