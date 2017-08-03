/*
 *  Linux utilities to executing test programs both under the debugger
 *  and outside of it.
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <prtypes.h>
#include <hasht.h>
#include "amvp.h"
#include "midbg.h"
#include "os_util.h"

/*
 * read everything from a file descriptor into newly allocated memory and
 * return it.
 */
#define BUF_SIZE 1024
char *
amvpu_readalloc(int fd)
{
    char * buffer = NULL;
    int size = 0;
    int next = 0;
    int left = 0;
    int bytes = -1;

    do {
	if (left == 0) {
	    char *new_buf;
	    size += BUF_SIZE;
	    left = BUF_SIZE;
    	    new_buf = realloc(buffer,size);
	    if (new_buf == NULL) {
		free(buffer);
		return NULL;
	    }
	    memset(&new_buf[next],0, BUF_SIZE);
	    buffer = new_buf;
	}
	bytes = read(fd, &buffer[next], left);
	if (bytes < 0) {
	     free(buffer);
	     return NULL;
	}
	left -= bytes;
	next += bytes;
    } while (bytes != 0);
    return buffer;
}



/* remove a directory and all it's contents */
int 
amvpu_rmdir_r(const char *path)
{
    DIR *dir;
    struct dirent *file;
    int rv;
    char buf[PATH_MAX];
    char *dummy;

   
    dummy = getcwd(buf, sizeof(buf));
    if (dummy == NULL) { 
	perror("getwd");
	return -1;
    }

    rv = chdir(path);
    if (rv < 0) {
	perror(path);
	fprintf(stderr,"chdir to %s failed\n",path);
	return rv;
    }

    dir = opendir(path);
    if (dir == NULL) {
	perror(path);
	fprintf(stderr,"opendir failed on %s\n",path);
	chdir(buf);
	return -1;
    }


    rv = 0;
    while ((file = readdir(dir)) != NULL) {
	if (strcmp(".",file->d_name) == 0) {
		continue;
	}
	if (strcmp("..",file->d_name) == 0) {
		continue;
	}
#ifdef notdef
	unsigned char type = file->d_type;
	
	if (type == DT_UNKNOWN)  {
	    struct stat stat_buf;
	    rv = lstat(file->d_name, &stat_buf);
	    if (rv < 0) {
		break;
	    }
	    if (SISDIR(stat_buf.st_mode)) {
		type = DT_DIR
	    }
	}
	if (type == DT_DIR) {
	    rv = amvpu_rmdir_r(file->d_name);
	} else {
	    rv = unlink(file->d_name);
	}
#else
/* for now, just unlink regular files. We know softoken won't be creating
 * subdirectories. this gives us safety in case we mess up path and clobber
 * our home directory */
	    rv = unlink(file->d_name);
#endif
	if (rv < 0) {
	    perror(file->d_name);
	    fprintf(stderr,"couldn't remove %s\n", file->d_name);
	    break;
	}
    }
    closedir(dir);
    if (rv < 0) {
        chdir(buf);
	return rv;
    }
    chdir(buf);
    return rmdir(path);
}

/* copy a file from source to dest. both source and dest should be paths
 * to regular files. Dest will be truncated if it exists and created if it
 * doesn't */
AMVP_RESULT
amvpu_copyfile(char *src,char *dest)
{
    int fsrc, fdest;
    char buf[4096];
    struct stat statbuf;
    size_t bytes_in, bytes_out;
    int rv;

    fsrc = open(src, O_RDONLY);
    if (fsrc < 0) {
        return AMVP_RESOURCE_FAIL;
    }

    rv = fstat(fsrc, &statbuf);
    if (rv < 0) {
        close(fsrc);
        return AMVP_RESOURCE_FAIL;
    }
    if (!S_ISREG(statbuf.st_mode)) {
        close(fsrc);
        return AMVP_RESOURCE_FAIL; 
    }
    fdest = open(dest, O_WRONLY|O_CREAT|O_TRUNC, statbuf.st_mode & 0777);
    if (fdest <0 ) {
        close(fsrc);
        return AMVP_RESOURCE_FAIL;
    }
    while ((bytes_in = read(fsrc, buf, sizeof(buf))) > 0) {
        bytes_out = write(fdest, buf, bytes_in);
        if (bytes_out != bytes_in) {
            break;
        }
    }
    close(fsrc);
    close(fdest);
    return bytes_in == 0 ? AMVP_SUCCESS: AMVP_RESOURCE_FAIL;
}

/*
 * run the external text program. All the output from standard error and 
 * standard out are saved in a log which is returned. The caller is 
 * responsible for freeing that collected log.
 */
char *
amvpu_exec_log(const char *client, const char *prog, 
	      char *const argv[], AMVP_RESULT *status)
{
    int pipefd[2];
    int rv;
    char *log;
    int pid;
    char buf[2048];

    rv = pipe(pipefd);
    if (rv < 0) {
	perror("pipe");
	fprintf(stderr, "Couldn't create a pipe\n");
	*status = AMVP_RESOURCE_FAIL;
	return NULL;
    }
    pid = fork();
    if (pid < 0) {
	perror("fork");
	fprintf(stderr, "Couldn't fork\n");
	*status = AMVP_RESOURCE_FAIL;
	return NULL;
    }
    if (pid == 0) {
	int mypid = getpid();
        /* close our pipe so we don't hang if the parent dies */
	close(pipefd[0]);

        /* set up a local directory to get an NSS database */
	sprintf(buf,"/tmp/amvp_%s_%d",client,mypid);
	rv = mkdir (buf, 0700);
	if (rv < 0) {
	     perror(&buf[0]);
	     fprintf(stderr, "Couldn't mkdir %s\n", buf);
	     exit(AMVP_RESOURCE_FAIL);
	}
	rv = chdir (buf);
	if (rv < 0) {
	     perror(&buf[0]);
	     fprintf(stderr, "Couldn't chdir %s\n", buf);
	     exit(AMVP_RESOURCE_FAIL);
	}

	/* set up stdin, stdout and stderr */
	close(0); /* no standard in */
	dup2(pipefd[1],1); /* standard out -> pipe */
	dup2(pipefd[1],2); /* standard error -> pipe */

	execvp(prog,argv);
	perror(prog);
	/* only gets here on failure */
	exit (AMVP_RESOURCE_FAIL);
    }

    close(pipefd[1]);
    log = amvpu_readalloc(pipefd[0]);
    if (log == NULL) {
	*status = AMVP_MALLOC_FAIL;
	return NULL;
    }
    waitpid(pid, &rv, 0);
    *status = WIFEXITED(rv) ? WEXITSTATUS(rv) : AMVP_RESOURCE_FAIL;

    /* clean up after ourselves */
    close(pipefd[0]);
    sprintf(buf,"/tmp/amvp_%s_%d",client,pid);
    rv = amvpu_rmdir_r(buf);
    if (rv < 0) {
	perror(&buf[0]);
	fprintf(stderr, "couldn't delete directory %s\n",buf);
    }
    return log;
}

/*
 * run the external test program under the debugger. All the output from 
 * standard error and standard out are saved in a log which is returned.
 * The caller is responsible for freeing that collected log. The debugger
 * session is controlled with the mi command interface for gdb using the
 * midbg library included in libamvp.a. Before the program gets launched,
 * 'callback' is called with a pointer to the midbg_session so that break
 * points and enviroment stuff can be set up. debugging control happens
 * through callbacks from the various breakpoint functions.
 */
char *amvpu_exec_debug(const char *client, const char *prog, 
			char *const argv[], AMVP_RESULT *status,
			amvpu_setup_callback callback, unsigned long filter)
{
    int reply[2];
    int command[2];
    int rv;
    char *log;
    int pid;
    char buf[2048];
    AMVP_RESULT rc;
    FILE *freply;
    FILE *fcommand;
    midbg_session *dbgSession;
    char *gdb_argv[] = {"gdb", "-q", "-i=mi", "**prog**", 0 };
    int i;

    /* Set the true program in argv. Doing this programatically
     *  means we can change the arguments using simply by changing
     *  the above argv list without having to change an array index
     *  by hand. */
    for (i=0; gdb_argv[i]; i++) {
	if (strcmp(gdb_argv[i],"**prog**") == 0) {
	    gdb_argv[i] = (char *)prog;
	    break;
	}
    }

    rv = pipe(reply);
    if (rv < 0) {
	perror("pipe");
	fprintf(stderr, "Couldn't create a pipe\n");
	*status = AMVP_RESOURCE_FAIL;
	return NULL;
    }
    rv = pipe(command);
    if (rv < 0) {
	perror("pipe");
	fprintf(stderr, "Couldn't create a pipe\n");
	*status = AMVP_RESOURCE_FAIL;
	return NULL;
    }
    pid = fork();
    if (pid < 0) {
	perror("fork");
	fprintf(stderr, "Couldn't fork\n");
	*status = AMVP_RESOURCE_FAIL;
	return NULL;
    }
    if (pid == 0) {
	int mypid = getpid();
        /* close our pipe so we don't hang if the parent dies */
	close(reply[0]);
	close(command[1]);

        /* set up a local directory to get an NSS database */
	sprintf(buf,"/tmp/amvp_%s_%d",client,mypid);
	rv = mkdir (buf, 0700);
	if (rv < 0) {
	     perror(&buf[0]);
	     fprintf(stderr, "Couldn't mkdir %s\n", buf);
	     exit(AMVP_RESOURCE_FAIL);
	}
	rv = chdir (buf);
	if (rv < 0) {
	     perror(&buf[0]);
	     fprintf(stderr, "Couldn't chdir %s\n", buf);
	     exit(AMVP_RESOURCE_FAIL);
	}

	/* set up stdin, stdout and stderr */
	dup2(command[0],0); /* standard in debugger commands */
	dup2(reply[1],1); /* standard out -> debugger replies */
	dup2(reply[1],2); /* standard error -> program log */

	execvp("gdb",gdb_argv);
	perror("gdb");
	/* only gets here on failure */
	exit (AMVP_RESOURCE_FAIL);
    }

    close(reply[1]);
    close(command[0]);
    freply = fdopen(reply[0],"r");
    fcommand = fdopen(command[1],"w");

    dbgSession = midbg_open_session(fcommand, freply, filter);

    rc = midbg_set_program_args(dbgSession, argv);
    if (rc != AMVP_SUCCESS) {
	goto cleanup;
    }

    if (callback) {
	rc = (*callback)(dbgSession);
	if (rc != AMVP_SUCCESS) goto cleanup;
    }

    rc = midbg_run_test(dbgSession);

 cleanup:   
    log = midbg_get_log(dbgSession);
    if (log == NULL) {
	*status = AMVP_MALLOC_FAIL;
	return NULL;
    }
    *status = rc;
    midbg_close_session(dbgSession);
    waitpid(pid, &rv, 0);

    /* clean up after ourselves */
    
    sprintf(buf,"/tmp/amvp_%s_%d",client,pid);
    rv = amvpu_rmdir_r(buf);
    if (rv < 0) {
	perror(&buf[0]);
	fprintf(stderr, "couldn't delete directory %s\n",buf);
    }
    return log;
}
