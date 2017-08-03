/*
 *  Debugging target
 */
#define _GNU_SOURCE 1
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pkcs11t.h>
#include "pk11table.h"
#include "amvp.h"
#include "os_util.h"

CK_UTF8CHAR PIN[] = "FipsTestPin13!";

int breakpoint1()
{
   return 1;
}

int breakpoint2()
{
   return 1;
}

int breakpoint3()
{
   return 1;
}

int breakpoint4()
{
   return 1;
}

int breakpoint5()
{
   return 1;
}

int breakpoint6()
{
   return 1;
}

int breakpoint7()
{
   return 1;
}

int breakpoint8()
{
   return 1;
}

const char *
pk11_error(CK_RV crv)
{
    const char *estr = getName(crv,ConstResult);
    return estr ? estr : "unknown error";
}

char *getlibpath(const void *addr)
{
    Dl_info dli;
    char *result;
    int rv;
    char *softoknLibName = PR_GetLibraryName(NULL,"softokn3");
    int libNameLen, fullPathLen, pathLen;

    libNameLen = strlen(softoknLibName);
    PR_FreeLibraryName(softoknLibName);

    rv = dladdr(addr, &dli);
    if (rv == 0) {
	return NULL;
    }
    fullPathLen = strlen(dli.dli_fname);
    if (libNameLen > fullPathLen) {
	return NULL;
    }
    pathLen = fullPathLen-libNameLen;
    result = malloc(pathLen+1);
    if (result == NULL) {
	return NULL;
    }
    memcpy(result,dli.dli_fname, pathLen);
    result[pathLen] = 0;
    return result;
}

#define CHK "chk"
int
copylibrary(char *library, char *source, char *dest)
{
    char *libname = NULL;
    char *sbuf = NULL,*dbuf = NULL;
    char *extension;
    size_t libLen, sLen, dLen;
    size_t sbufLen, dbufLen;
    size_t offset;
    int rv = 0;
    AMVP_RESULT arv;

    sLen = strlen(source);
    dLen = strlen(dest);

    libname = PR_GetLibraryName(NULL,library);
    if (libname == NULL) {
	rv = -1;
	goto cleanup;
    }
    libLen = strlen(libname);
    sbufLen = libLen+sLen+sizeof(CHK);
    sbuf = malloc(sbufLen);
    if (sbuf == NULL) {
	rv = -1;
	goto cleanup;
    }
    dbufLen = libLen+dLen+sizeof(CHK);
    dbuf = malloc(dbufLen);
    if (dbuf == NULL) {
	rv = -1;
	goto cleanup;
    }
    memcpy(sbuf, source, sLen);
    memcpy(&sbuf[sLen],libname,libLen);
    sbuf[sLen+libLen] = 0;
    memcpy(dbuf, dest, dLen);
    memcpy(&dbuf[dLen],libname,libLen);
    dbuf[dLen+libLen] = 0;

    arv = amvpu_copyfile(sbuf,dbuf);
    if (arv < 0) {
	rv = -1;
	goto cleanup;
    }
    extension = strrchr(libname,'.');
    if (extension == NULL) {
	rv = -1;
	goto cleanup;
    }
    offset = extension-libname+1;
    memcpy(&sbuf[sLen+offset],CHK, sizeof(CHK));
    memcpy(&dbuf[dLen+offset],CHK, sizeof(CHK));

    arv = amvpu_copyfile(sbuf,dbuf);
    if (arv != AMVP_SUCCESS) {
	rv = -1;
	goto cleanup;
    }
cleanup:
    free(dbuf);
    free(sbuf);
    if (libname) {
        PR_FreeLibraryName(libname);
    }
    return rv;
}

int
mangle_unmangle(char *lib, int unmangle)
{
    int fd;
    char b;
    size_t bytes;
    char *file;
    char *prefix = unmangle ? "un": "";

    file = PR_GetLibraryName(NULL,lib);
    if (file == NULL) {
	return -1;
    }

    fprintf(stderr,":%smangling file %s\n", prefix, file);
    fd = open(file,O_RDWR);
    if (fd < 0) {
	perror(file);
    	PR_FreeLibraryName(file);
	return -1;
    }
    lseek(fd,-1,SEEK_END);
    bytes = read(fd, &b, 1);
    if (bytes != 1) {
	fprintf(stderr,">%smangle failed to read %s \n",prefix, file);
	close(fd);
    	PR_FreeLibraryName(file);
	return -1;
    }
    b = b ^ 0x1;
    lseek(fd,-1,SEEK_END);
    bytes = write(fd,&b,1);
    if (bytes != 1) {
	fprintf(stderr,">%smangle failed to write %s \n",prefix, file);
	close(fd);
    	PR_FreeLibraryName(file);
	return -1;
    }
    close(fd);
    PR_FreeLibraryName(file);
    return 0;
}

int
unmangle(char *lib)
{
   return mangle_unmangle(lib,1);
}

int
mangle(char *lib)
{
   return mangle_unmangle(lib,0);
}

CK_SLOT_ID
get_slotID(CK_FUNCTION_LIST_PTR function_list)
{
    CK_SLOT_ID slotID = -1;
    CK_ULONG count=1;
    CK_RV crv;

    crv = function_list->C_GetSlotList(CK_TRUE, &slotID, &count);
    if (crv != CKR_OK) {
	return -1;
    }
    if (count < 1) {
	return -1;
    }
    return slotID;
}

CK_RV
db_init(CK_FUNCTION_LIST_PTR function_list, CK_SLOT_ID slotID)
{
    CK_RV crv;
    CK_TOKEN_INFO token_info;
    CK_SESSION_HANDLE session;

    crv = function_list->C_GetTokenInfo(slotID, &token_info);
    if (crv != CKR_OK) {
	return crv;
    }

    /* database is already initialized */
    if (token_info.flags & CKF_USER_PIN_INITIALIZED) {
	return CKR_OK;
    }

    crv = function_list->C_OpenSession(slotID, 
		CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (crv != CKR_OK) {
	return crv;
    }

    crv = function_list->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)"", 0);
    if (crv != CKR_OK) {
	return crv;
    }

    crv = function_list->C_InitPIN(session, PIN, sizeof(PIN)-1);
    if (crv != CKR_OK) {
	return crv;
    }

    crv = function_list->C_Logout(session);
    if (crv != CKR_OK) {
	return crv;
    }

    crv = function_list->C_CloseSession(session);
    if (crv != CKR_OK) {
	return crv;
    }

    return CKR_OK;
}

#define NUM_ELEM(array) (sizeof(array) / sizeof(array[0]))

int
main(int argc, char *argv[])
{
    void *handle;
    const char *library_name = "libsoftokn3.so";
    CK_C_INITIALIZE_ARGS init_args;
    CK_C_GetFunctionList pC_GetFunctionList;
    CK_FUNCTION_LIST_PTR function_list;
    CK_SESSION_HANDLE session;
    unsigned char bytes[256];
    unsigned char zero[256];
    char * module_spec = 
     "configdir='dbm:.' certPrefix='' keyPrefix='' secmod=secmod.db flags= ";
    CK_SLOT_ID slotID;
    CK_RV crv;
    CK_KEY_TYPE rsatype = CKK_RSA;
    CK_MECHANISM rsaKeyPairGenMech;
    CK_BYTE subject[] = { "RSA Private Key" };
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
    CK_BYTE id[] = { "RSA123" };
    CK_ATTRIBUTE rsaPubKeyTemplate[9];
    CK_ATTRIBUTE rsaPrivKeyTemplate[11];
    CK_OBJECT_HANDLE hRSApubKey;
    CK_OBJECT_HANDLE hRSAprivKey;
    CK_MECHANISM rsaMech;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_ULONG len;

    char *simple_test_args[] = { "simple_test", "-F", 0 };
    char *simple_test_args_success[] = { "simple_test", "-S", 0 };
    char *libraryPath;
    char *log, buf[2048];
    AMVP_RESULT status;
    int rv;

    memset(zero,0,sizeof(zero));

    init_args.CreateMutex = NULL;
    init_args.DestroyMutex = NULL;
    init_args.LockMutex  = NULL;
    init_args.UnlockMutex = NULL;
    init_args.pReserved = NULL;
    init_args.LibraryParameters = (CK_CHAR_PTR *)module_spec;
    init_args.flags = CKF_OS_LOCKING_OK;

    fprintf(stderr,":Starting the debugger driven tests, loading the library\n");
    fflush(stderr);

    handle = dlopen(library_name, RTLD_LOCAL|RTLD_NOW);
    if (handle == NULL) {
	perror(library_name);
	return AMVP_RESOURCE_FAIL;
    }

    /* debugger will verify that the selftests ran by breakpoint1,
     * and exit if they didn't */
    breakpoint1(); 
    fprintf(stderr,":library loaded\n");
    fflush(stderr);

    /* initialize NSS */
    pC_GetFunctionList = dlsym(handle, "FC_GetFunctionList");
    if (pC_GetFunctionList == NULL) {
	perror(library_name);
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    crv = (*pC_GetFunctionList)(&function_list);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_GetFunctionList failed with 0x%08lx (%s)\n",
						crv, pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* C_Initialize */
    crv = function_list->C_Initialize(&init_args);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_Initialized failed with 0x%08lx (%s)\n",
						crv, pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* libnssdbm doesn't get loaded until init time, The debugger will 
     * make sure it's
     * loaded and the self tests have ran  before here*/
    breakpoint2();

    slotID = get_slotID(function_list);
    if (slotID == -1) {
	fprintf(stderr,">couldn't find a slot \n");
	return AMVP_CRYPTO_MODULE_FAIL;
    }
    fprintf(stderr, ":Now verifying continuous prng test\n");

    /* C_InitToken if necessary*/
    crv = db_init(function_list, slotID);
    if (crv != CKR_OK) {
	fprintf(stderr,">initializing database failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    crv = function_list->C_OpenSession(slotID, CKF_SERIAL_SESSION,
					NULL, NULL, &session);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_OpenSession failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* Set up breakpoints to cause the continuous random number test to fail*/
    breakpoint3();

    /* debugger will fail the continuous random number test for us */
    /* C_GenerateRandom  */
    memset(bytes, 0, sizeof(bytes));
    crv = function_list->C_GenerateRandom(session, bytes, sizeof(bytes));
    /* if success and or has data, fail */
    if (crv == CKR_OK) {
	fprintf(stderr,
		">C_GenerateRandom succeeded when we expected a failure\n");
	return AMVP_CRYPTO_MODULE_FAIL;
    } else {
	fprintf(stderr, ":C_Generate Random failed as expected with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
    }

    if (memcmp(bytes, zero, sizeof(bytes)) != 0) {
	fprintf(stderr,">C_GenerateRandom produced output on failure\n");
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* clear the error state */	
    crv = function_list->C_Finalize(NULL);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_Finalize failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* clear out all our breakpoints */
    breakpoint4();


    fprintf(stderr, ":Now testing pairwise consistancy checks\n");

    /* reinitialize the module */
    crv = function_list->C_Initialize(&init_args);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_Initialized failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    crv = function_list->C_OpenSession(slotID, CKF_SERIAL_SESSION,
					NULL, NULL, &session);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_OpenSession failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* Generate Key Pair requires login */
    crv = function_list->C_Login(session, CKU_USER, PIN, sizeof(PIN)-1);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_Login failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    rsaKeyPairGenMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    rsaKeyPairGenMech.pParameter = NULL;
    rsaKeyPairGenMech.ulParameterLen = 0;

    rsaPubKeyTemplate[0].type = CKA_KEY_TYPE;
    rsaPubKeyTemplate[0].pValue = &rsatype;
    rsaPubKeyTemplate[0].ulValueLen = sizeof(rsatype);
    rsaPubKeyTemplate[1].type = CKA_PRIVATE;
    rsaPubKeyTemplate[1].pValue = &ck_true;
    rsaPubKeyTemplate[1].ulValueLen = sizeof(ck_true);
    rsaPubKeyTemplate[2].type = CKA_ENCRYPT;
    rsaPubKeyTemplate[2].pValue = &ck_true;
    rsaPubKeyTemplate[2].ulValueLen = sizeof(ck_true);
    rsaPubKeyTemplate[3].type = CKA_DECRYPT;
    rsaPubKeyTemplate[3].pValue = &ck_true;
    rsaPubKeyTemplate[3].ulValueLen = sizeof(ck_true);
    rsaPubKeyTemplate[4].type = CKA_VERIFY;
    rsaPubKeyTemplate[4].pValue = &ck_true;
    rsaPubKeyTemplate[4].ulValueLen = sizeof(ck_true);
    rsaPubKeyTemplate[5].type = CKA_SIGN;
    rsaPubKeyTemplate[5].pValue = &ck_true;
    rsaPubKeyTemplate[5].ulValueLen = sizeof(ck_true);
    rsaPubKeyTemplate[6].type = CKA_WRAP;
    rsaPubKeyTemplate[6].pValue = &ck_true;
    rsaPubKeyTemplate[6].ulValueLen = sizeof(ck_true);
    rsaPubKeyTemplate[7].type = CKA_MODULUS_BITS;
    rsaPubKeyTemplate[7].pValue = &modulusBits;
    rsaPubKeyTemplate[7].ulValueLen = sizeof(modulusBits);
    rsaPubKeyTemplate[8].type = CKA_PUBLIC_EXPONENT;
    rsaPubKeyTemplate[8].pValue = publicExponent;
    rsaPubKeyTemplate[8].ulValueLen = sizeof(publicExponent);

    rsaPrivKeyTemplate[0].type = CKA_KEY_TYPE;
    rsaPrivKeyTemplate[0].pValue = &rsatype;
    rsaPrivKeyTemplate[0].ulValueLen = sizeof(rsatype);
    rsaPrivKeyTemplate[1].type = CKA_TOKEN;
    rsaPrivKeyTemplate[1].pValue = &ck_false;
    rsaPrivKeyTemplate[1].ulValueLen = sizeof(ck_true);
    rsaPrivKeyTemplate[2].type = CKA_PRIVATE;
    rsaPrivKeyTemplate[2].pValue = &ck_true;
    rsaPrivKeyTemplate[2].ulValueLen = sizeof(ck_true);
    rsaPrivKeyTemplate[3].type = CKA_SUBJECT;
    rsaPrivKeyTemplate[3].pValue = subject;
    rsaPrivKeyTemplate[3].ulValueLen = sizeof(subject);
    rsaPrivKeyTemplate[4].type = CKA_ID;
    rsaPrivKeyTemplate[4].pValue = id;
    rsaPrivKeyTemplate[4].ulValueLen = sizeof(id);
    rsaPrivKeyTemplate[5].type = CKA_SENSITIVE;
    rsaPrivKeyTemplate[5].pValue = &ck_true;
    rsaPrivKeyTemplate[5].ulValueLen = sizeof(ck_true);
    rsaPrivKeyTemplate[6].type = CKA_ENCRYPT;
    rsaPrivKeyTemplate[6].pValue = &ck_true;
    rsaPrivKeyTemplate[6].ulValueLen = sizeof(ck_true);
    rsaPrivKeyTemplate[7].type = CKA_DECRYPT;
    rsaPrivKeyTemplate[7].pValue = &ck_true;
    rsaPrivKeyTemplate[7].ulValueLen = sizeof(ck_true);
    rsaPrivKeyTemplate[8].type = CKA_VERIFY;
    rsaPrivKeyTemplate[8].pValue = &ck_true;
    rsaPrivKeyTemplate[8].ulValueLen = sizeof(ck_true);
    rsaPrivKeyTemplate[9].type = CKA_SIGN;
    rsaPrivKeyTemplate[9].pValue = &ck_true;
    rsaPrivKeyTemplate[9].ulValueLen = sizeof(ck_true);
    rsaPrivKeyTemplate[10].type = CKA_UNWRAP;
    rsaPrivKeyTemplate[10].pValue = &ck_true;
    rsaPrivKeyTemplate[10].ulValueLen = sizeof(ck_true);

    /* set break point in pairwise consistancy check to make it fail */
    fprintf(stderr, ":calling breakpoint 5\n");
    breakpoint5();

    /* C_GenerateKeyPair - the debugger will make sure the pairwise 
     * consistency check fails */
    hRSApubKey = CK_INVALID_HANDLE;
    hRSAprivKey = CK_INVALID_HANDLE;
    crv = function_list->C_GenerateKeyPair(session, &rsaKeyPairGenMech,
                                               rsaPubKeyTemplate,
                                               NUM_ELEM(rsaPubKeyTemplate),
                                               rsaPrivKeyTemplate,
                                               NUM_ELEM(rsaPrivKeyTemplate),
                                               &hRSApubKey, &hRSAprivKey);
    /* if success and or has data, fail */
    fprintf(stderr, ":C_GenerateKeyPair return 0x%lx (%s)\n",
						crv,pk11_error(crv));
    if (crv == CKR_OK) {
	fprintf(stderr,
		">C_GenerateKeyPair succeeded when we expected a failure\n");
        fflush(stderr);
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    if ((hRSApubKey != CK_INVALID_HANDLE) 
		|| (hRSAprivKey != CK_INVALID_HANDLE)) {
	fprintf(stderr,">C_GenerateRandom produced output on failure\n");
        fflush(stderr);
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* F_Finalize * reset error state */
    crv = function_list->C_Finalize(NULL);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_Finalize failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
        fflush(stderr);
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* clear out the rest of our breakpoints so we can generate a key pair */
    breakpoint6();

    /* reinitialize the module */
    crv = function_list->C_Initialize(&init_args);
    if (crv != CKR_OK) {
	fprintf(stderr,"C_Initialized failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    crv = function_list->C_OpenSession(slotID, CKF_SERIAL_SESSION,
					NULL, NULL, &session);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_OpenSession failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* Generate Key Pair requires login */
    crv = function_list->C_Login(session, CKU_USER, PIN, sizeof(PIN)-1);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_Login failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* C_GenerateKeyPair - this time succeed so we can use the keys */
    hRSApubKey = CK_INVALID_HANDLE;
    hRSAprivKey = CK_INVALID_HANDLE;
    crv = function_list->C_GenerateKeyPair(session, &rsaKeyPairGenMech,
                                               rsaPubKeyTemplate,
                                               NUM_ELEM(rsaPubKeyTemplate),
                                               rsaPrivKeyTemplate,
                                               NUM_ELEM(rsaPrivKeyTemplate),
                                               &hRSApubKey, &hRSAprivKey);
    /* if success and or has data, fail */
    fprintf(stderr, ":C_GenerateKeyPair return 0x%lx (%s)\n",
						crv,pk11_error(crv));
    if (crv != CKR_OK) {
	fprintf(stderr,">C_GenerateKeyPair failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
        fflush(stderr);
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* set a breakpoint at rsa_PrivateKeyOpCRTCheckedPubKey */
    breakpoint7();

    rsaMech.mechanism = CKM_RSA_PKCS;
    rsaMech.pParameter = NULL;
    rsaMech.ulParameterLen = 0;

    /* sign something */
    crv = function_list->C_SignInit(session, &rsaMech, hRSAprivKey);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_SignInit failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
        fflush(stderr);
	return AMVP_CRYPTO_MODULE_FAIL;
    }


    memset(bytes, 0, 64);
    len = sizeof(bytes);
    crv = function_list->C_Sign(session, bytes, 64, bytes, &len);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_Sign failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
        fflush(stderr);
	return AMVP_CRYPTO_MODULE_FAIL;
    }
	

    /* verify that rsa_PrivateKeyOpCRTCheckedPubKey was called */
    breakpoint8();

    /* F_Finalize close down. */
    crv = function_list->C_Finalize(NULL);
    if (crv != CKR_OK) {
	fprintf(stderr,">C_Finalize failed with 0x%08lx (%s)\n",
						crv,pk11_error(crv));
        fflush(stderr);
	return AMVP_CRYPTO_MODULE_FAIL;
    }

    /* get the library path before we release the library */
    libraryPath = getlibpath(function_list);
    if (libraryPath == NULL) {
	perror(">failed to get the library path");
        fflush(stderr);
	return AMVP_RESOURCE_FAIL;
    }

    /* unload the library */
    dlclose(handle);

    /* now test to make sure test the integrity of dbm and freebl */
    fprintf(stderr, ":Copying library files from %s to %s\n",
					libraryPath, getcwd(buf, sizeof(buf)));
    fflush(stderr);


    rv =copylibrary("softokn3",libraryPath,"./");
    if (rv < 0) {
	perror(">copy softokn3");
        fflush(stderr);
	return AMVP_RESOURCE_FAIL;
    }

    rv =copylibrary("freeblpriv3",libraryPath,"./");
    if (rv < 0) {
	perror(">copy freeblpriv3");
        fflush(stderr);
	return AMVP_RESOURCE_FAIL;
    }

    rv =copylibrary("nssdbm3",libraryPath,"./");
    if (rv < 0) {
	perror(">copy nssdbm3");
        fflush(stderr);
	return AMVP_RESOURCE_FAIL;
    }

    /* set env LD_LIBRARY_PATH */
    rv = setenv("LD_LIBRARY_PATH",getcwd(buf, sizeof(buf)),1);
    if (rv < 0) {
	perror(">failed to set LD_LIBRARY_PATH");
	fflush(stderr);
	return AMVP_RESOURCE_FAIL;
    }

    rv = mangle("softokn3");
    if (rv < 0) {
	perror(">mangle softokn3");
        fflush(stderr);
	return AMVP_RESOURCE_FAIL;
    }


    fprintf(stderr,":attempting to open FIPS token with mangled softokn3\n");
    fflush(stderr);
    log = amvpu_exec_log("simple_test","simple_test",
			 simple_test_args, &status);
    if (log) {
	printf("%s",log);
	free(log);
	fflush(stdout);
    }
    if (status !=  0) {
	fprintf(stderr,"> integrity check on softokn3 failed to trigger\n");
        fflush(stderr);
	return status;
    }
    rv = unmangle("softokn3");
    if (rv < 0) {
	perror(">unmangle softokn3");
        fflush(stderr);
	return AMVP_RESOURCE_FAIL;
    }
    rv = mangle("freeblpriv3");
    if (rv < 0) {
	perror(">mangle freeblpriv3");
        fflush(stderr);
	return AMVP_RESOURCE_FAIL;
    }
    fprintf(stderr,":attempting to open FIPS token with mangled freeblpriv3\n");
    fflush(stderr);
    log = amvpu_exec_log("simple_test","simple_test",
			simple_test_args, &status);
    if (log) {
	printf("%s",log);
	free(log);
	fflush(stdout);
    }
    if (status != AMVP_SUCCESS) {
	fprintf(stderr,"> integrity check on libfreeblpriv3 failed to trigger\n");
        fflush(stderr);
	return status;
    }
    
    rv = unmangle("freeblpriv3");
    if (rv < 0) {
	perror(">unmangle freeblpriv3");
        fflush(stderr);
	return AMVP_RESOURCE_FAIL;
    }
    rv = mangle("nssdbm3");
    if (rv < 0) {
	perror(">mangle nssdbm3");
        fflush(stderr);
	return AMVP_RESOURCE_FAIL;
    }
    fprintf(stderr,":attempting to open FIPS token with mangled nssdbm3\n");
    fflush(stderr);
    log = amvpu_exec_log("simple_test","simple_test",
			simple_test_args, &status);
    if (log) {
	printf("%s",log);
	fflush(stdout);
	free(log);
    }
    if (status != 0) {
	fprintf(stderr,"> integrity check on nssdbm3 failed to trigger\n");
        fflush(stderr);
	return status;
    }
    rv = unmangle("nssdbm3");
    if (rv < 0) {
	perror(">unmangle nssdbm3");
        fflush(stderr);
	return AMVP_RESOURCE_FAIL;
    }
    fprintf(stderr,":attempting to open FIPS token with clean libraries\n");
    fflush(stderr);
    log = amvpu_exec_log("simple_test","simple_test",
			simple_test_args_success, &status);
    if (log) {
	printf("%s",log);
	free(log);
	fflush(stdout);
    }
    if (status != 0) {
	fprintf(stderr,"> integrity check failed to trigger on clean databases\n");
        fflush(stderr);
	return status;
    }
    
    fprintf(stderr,":debug program completed successfully\n");
    fflush(stderr);

    return 0;
}
