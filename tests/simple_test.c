/*
 *  Debugging target
 */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pkcs11t.h>
#include "pk11table.h"
#include "amvp.h"

const char *
pk11_error(CK_RV crv)
{
    const char *estr = getName(crv,ConstResult);
    return estr ? estr : "unknown error";
}


int
main(int argc, char *argv[])
{
    void *handle;
    const char *library_name = "libsoftokn3.so";
    CK_C_INITIALIZE_ARGS init_args;
    CK_C_GetFunctionList pC_GetFunctionList;
    CK_FUNCTION_LIST_PTR function_list;
    char * module_spec = 
		"configdir='dbm:.' certPrefix='' keyPrefix='' secmod=secmod.db flags= ";
    CK_RV crv;
    int expect_fail = 0;

    if (argc != 2) {
    	fprintf(stderr, "Simple Test: invalid arguents argc = %d\n", argc);
	return AMVP_RESOURCE_FAIL;
    }
    if (strcmp(argv[1],"-F") == 0) {
	expect_fail = 1;
    } else if (strcmp(argv[1],"-S") == 0) {
	expect_fail = 0;
    } else {
    	fprintf(stderr, "Simple Test: invalid arguents\n");
	return AMVP_RESOURCE_FAIL;
    }

    init_args.CreateMutex = NULL;
    init_args.DestroyMutex = NULL;
    init_args.LockMutex  = NULL;
    init_args.UnlockMutex = NULL;
    init_args.pReserved = NULL;
    init_args.LibraryParameters = (CK_CHAR_PTR *)module_spec;
    init_args.flags = CKF_OS_LOCKING_OK;

    printf("Simple Test running, Expecting %s\n", 
				expect_fail ? "Failure": "Success");
    fflush(stdout);

    handle = dlopen(library_name, RTLD_LOCAL|RTLD_NOW);
    if (handle == NULL) {
	perror(library_name);
    	fprintf(stderr, "Simple Test: failed to load library\n");
	return AMVP_RESOURCE_FAIL;
    }

    /* initialize NSS */
    pC_GetFunctionList = dlsym(handle, "FC_GetFunctionList");
    if (pC_GetFunctionList == NULL) {
	perror(library_name);
    	fprintf(stderr, "Simple Test: failed to find FIPS function list\n");
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    crv = (*pC_GetFunctionList)(&function_list);
    if (crv != CKR_OK) {
	fprintf(stderr,
		"Simple Test: C_GetFunctionList failed with 0x%08lx (%s)\n",
						crv, pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* C_Initialize */
    crv = function_list->C_Initialize(&init_args);
    if (crv != CKR_OK) {
	fprintf(stderr,
	"Simple Test: C_Initialized failed %swith 0x%08lx (%s)\n",
		expect_fail ? "as expected ":"", crv, pk11_error(crv));

	return  expect_fail ? AMVP_SUCCESS : AMVP_CRYPTO_MODULE_FAIL;
    }

    /* clear the error state */	
    crv = function_list->C_Finalize(NULL);
    if (crv != CKR_OK) {
	fprintf(stderr,"C_Finalize failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }
    printf( "Simple Test: C_Initialized %ssucceeded\n", 
				expect_fail ? "unexpectedly ":"");

    return expect_fail ? AMVP_CRYPTO_MODULE_FAIL: AMVP_SUCCESS;
}
	


