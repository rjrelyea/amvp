/*
 * 
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include "amvp.h"
#include "app_lcl.h"

AMVP_RESULT does_not_apply(AMVP_TEST_CASE *tc, const char *info)
{
	tc->test_response = AMVP_TEST_NOT_RELEVANT;
	tc->log_count = 0;
	tc->info = info;
	return AMVP_SUCCESS;
}

AMVP_RESULT not_implemented(AMVP_TEST_CASE *tc)
{
	tc->test_response = AMVP_TEST_NOT_IMPLEMENTED;
	tc->log_count = 0;
	tc->info = NULL;
	return AMVP_UNSUPPORTED_OP;
}

AMVP_RESULT certutil_db(AMVP_TEST_CASE *tc)
{
   return not_implemented(tc);
}

AMVP_RESULT state(AMVP_TEST_CASE *tc,  const char *info)
{
   return not_implemented(tc);
}

AMVP_RESULT finite_state_machine(AMVP_TEST_CASE *tc)
{
   return not_implemented(tc);
}
   
AMVP_RESULT self_test_verify(AMVP_TEST_CASE *tc)
{
   return not_implemented(tc);
}

AMVP_RESULT csp_protection(AMVP_TEST_CASE *tc)
{
   return not_implemented(tc);
}

AMVP_RESULT zeroize_test(AMVP_TEST_CASE *tc)
{
   return not_implemented(tc);
}


void output_log_cleanup(AMVP_TEST_CASE *tc)
{
    int i;
    for (i=0; i < tc->log_count; i++) {
	free((char *)tc->log[i]);
	tc->log[i] = 0;
    }
}

#define BUF_SIZE 1024
char *readalloc(int fd)
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
int rmdir_r(const char *path)
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
	    rv = rmdir_r(file->d_name);
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

char *exec_pk11_mode(char *const argv[], AMVP_RESULT *status)
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
	sprintf(buf,"/tmp/amvp_nss_%d",mypid);
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

	

	execvp(PK11MODE,argv);
	perror("execvp "PK11MODE);
	/* only gets here on failure */
	exit (AMVP_RESOURCE_FAIL);
    }

    close(pipefd[1]);
    log = readalloc(pipefd[0]);
    if (log == NULL) {
	*status = AMVP_MALLOC_FAIL;
	return NULL;
    }
    waitpid(pid, &rv, 0);
    *status = WIFEXITED(rv) ? WEXITSTATUS(rv) : AMVP_RESOURCE_FAIL;

    /* clean up after ourselves */
    close(pipefd[0]);
    sprintf(buf,"/tmp/amvp_nss_%d",pid);
    rv = rmdir_r(buf);
    if (rv < 0) {
	perror(&buf[0]);
	fprintf(stderr, "couldn't delete directory %s\n",buf);
    }
    return log;
}
    

AMVP_RESULT pk11_mode(AMVP_TEST_CASE *tc, char *const argv[], const char *info)
{
   char *out_log;
   AMVP_RESULT rv, status;


   out_log = exec_pk11_mode(argv,&status);
   rv = AMVP_SUCCESS;
   if (out_log == NULL) {
	tc->test_response = AMVP_TEST_FAILED;
	tc->log_count = 0;
	tc->info = NULL;
	rv = status;
   } else if (status != AMVP_SUCCESS) {
	tc->test_response = AMVP_TEST_FAILED_WITH_LOG;
	tc->log_count = 1;
	tc->info = NULL;
	tc->log[0] =  out_log;
	tc->cleanup =  output_log_cleanup;
   } else {
	tc->test_response = AMVP_TEST_PASSED_WITH_LOG;
	tc->log_count = 1;
	tc->info = info;
	tc->log[0] =  out_log;
	tc->cleanup =  output_log_cleanup;
   }
	
   return rv;
}

AMVP_RESULT pk11_mode_error(AMVP_TEST_CASE *tc, char *const argv[], const char *info)
{
   return not_implemented(tc);
}

AMVP_RESULT pk11_mode_log(AMVP_TEST_CASE *tc, char *const args[], const char *info)
{
   return not_implemented(tc);
}


AMVP_RESULT amvp_handle_test(AMVP_TEST_CASE *tc)
{
   char *FV_argv[] = {"-F","-v", 0 };

   switch (tc->test_type) {
   case AMVP_TE01_03_02:
	return pk11_mode(tc, FV_argv, "See FIPS MODE and Hybrid MODE");
   case AMVP_TE01_04_02:
	return pk11_mode(tc, FV_argv, "See FIPS MODE and Hybrid MODE");
   case AMVP_TE02_06_02:
	return state(tc, "xxxx");
   case AMVP_TE02_06_04:
	return state(tc, "All inputs and outputs are tested");
   case AMVP_TE02_13_03:
	return does_not_apply(tc, "Hardware only");
   case AMVP_TE02_14_02:
	return pk11_mode(tc, FV_argv, "NSS never outputs CSPS");
   case AMVP_TE03_02_02:
	return pk11_mode(tc, FV_argv, "NSS has only one operator");
   case AMVP_TE03_11_02:
	return pk11_mode(tc, FV_argv, "See return codes and status function");
   case AMVP_TE03_11_03:
	return pk11_mode_log(tc, FV_argv, "See audit log"); /* grab syslog */
   case AMVP_TE03_03_02:
	return does_not_apply(tc, "NSS does not support bypass");
   case AMVP_TE03_14_02:
   case AMVP_TE03_15_02:
	return pk11_mode(tc, FV_argv, 
		"Crypto officer login for Initing database pasword,"
		" user logged in for other access");
   case AMVP_TE03_17_02:
	return pk11_mode(tc, FV_argv, "see C_Login tests");
   case AMVP_TE03_18_02:
	return pk11_mode(tc, FV_argv, 
		"Crypto officer login for Initing database pasword,"
		" user logged in for other access");
   case AMVP_TE03_21_02:
	return does_not_apply(tc, "Hardware only");
   case AMVP_TE03_22_02:
	 /* create a database with a password */
	 /* change the database password */
	 /* access the database with old password, expect failure */
	 return certutil_db(tc); 
   case AMVP_TE03_23_02:
	return pk11_mode(tc, FV_argv, "see C_Login tests");
   case AMVP_TE03_24_02:
	return pk11_mode(tc, FV_argv, "see C_Login tests");
   case AMVP_TE04_03_01:
	/* testing error states */
	return pk11_mode_error(tc,FV_argv,"program should fail do to errors");
   case AMVP_TE04_05_08:
	return finite_state_machine(tc);
   case AMVP_TE07_01_02:
   case AMVP_TE07_02_02:
	return csp_protection(tc);
   case AMVP_TE07_15_02:
   case AMVP_TE07_15_03:
   case AMVP_TE07_15_04:
	return does_not_apply(tc, 
			"NSS does not provide intermediate key output");
   case AMVP_TE07_23_03:
	return does_not_apply(tc, "NSS does not provide use seed keys");
   case AMVP_TE07_25_02:
	return does_not_apply(tc, "NSS only supports one entity");
   case AMVP_TE07_27_02:
   case AMVP_TE07_29_02:
   case AMVP_TE07_32_02:
	return does_not_apply(tc, 
			"NSS does not support an external display device");
   case AMVP_TE07_39_02:
	return pk11_mode(tc, FV_argv, 
		"Crypto officer login for Initing database pasword,"
		" user logged in for other access");
   case AMVP_TE07_41_02:
	return zeroize_test(tc);
   case AMVP_TE09_04_03:
   case AMVP_TE09_05_03:
   case AMVP_TE09_06_02:
   case AMVP_TE09_07_03:
   case AMVP_TE09_09_02:
   case AMVP_TE09_10_02:
   case AMVP_TE09_12_02:
   case AMVP_TE09_16_01:
   case AMVP_TE09_16_02:
   case AMVP_TE09_19_03:
   case AMVP_TE09_22_07:
   case AMVP_TE09_24_01:
   case AMVP_TE09_27_01:
   case AMVP_TE09_27_02:
   case AMVP_TE09_31_01:
	return self_test_verify(tc);
   case AMVP_TE09_35_04:
   case AMVP_TE09_35_05:
	return does_not_apply(tc, "NSS does not load firmware");
   default:
	break;
   }
   return not_implemented(tc);
}
