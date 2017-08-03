/*
 * pk11mode.c - Test FIPS or NONFIPS Modes for the NSS PKCS11 api.
 *              The goal of this program is to test every function
 *              entry point of the PKCS11 api at least once.
 *              To test in FIPS mode: pk11mode
 *              To test in NONFIPS mode: pk11mode -n
 *              usage: pk11mode -h
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#if defined(XP_UNIX) 
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

#ifdef _WIN32
#include <windows.h>
#define LIB_NAME "softokn3.dll"
#endif
#include "prlink.h"
#include "prprf.h"
#include "plgetopt.h"
#include "prenv.h"

#include "pk11table.h"

#define NUM_ELEM(array) (sizeof(array) / sizeof(array[0]))

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

/* Returns constant error string for "CRV".
 * Returns "unknown error" if errNum is unknown.
 */
const char *
PKM_CK_RVtoStr(CK_RV errNum)
{
    const char *err;

    err = getName(errNum, ConstResult);

    if (err)
        return err;

    return "unknown error";
}

#include "pkcs11p.h"

typedef struct CK_C_INITIALIZE_ARGS_NSS {
    CK_CREATEMUTEX CreateMutex;
    CK_DESTROYMUTEX DestroyMutex;
    CK_LOCKMUTEX LockMutex;
    CK_UNLOCKMUTEX UnlockMutex;
    CK_FLAGS flags;
    /* The official PKCS #11 spec does not have a 'LibraryParameters' field, but
     * a reserved field. NSS needs a way to pass instance-specific information
     * to the library (like where to find its config files, etc). This
     * information is usually provided by the installer and passed uninterpreted
     * by NSS to the library, though NSS does know the specifics of the softoken
     * version of this parameter. Most compliant PKCS#11 modules expect this
     * parameter to be NULL, and will return CKR_ARGUMENTS_BAD from
     * C_Initialize if Library parameters is supplied. */
    CK_CHAR_PTR *LibraryParameters;
    /* This field is only present if the LibraryParameters is not NULL. It must
     * be NULL in all cases */
    CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS_NSS;

#include "pkcs11u.h"


#define DSA_BITS 2048
#define DSA_SUB_PRIME_BITS 256
#define RSA_BITS 2048
#define TLS_RANDOM_LEN 32
#define MAX_SIG_SZ (RSA_BITS/8) 
#define MAX_CIPHER_SZ (RSA_BITS/8)
#define MAX_DATA_SZ 64
#define MAX_DIGEST_SZ 64
#define HMAC_MAX_LENGTH 64
#define FIPSMODE 0
#define NONFIPSMODE 1
#define HYBRIDMODE 2
#define NOMODE 3
int MODE = FIPSMODE;

CK_BBOOL true = CK_TRUE;
CK_BBOOL false = CK_FALSE;
static const CK_BYTE PLAINTEXT[] = { "Firefox  Rules!" };
static const CK_BYTE PLAINTEXT_PAD[] =
    { "Firefox and thunderbird rule the world!" };
CK_ULONG NUMTESTS = 0;

static const char *slotFlagName[] = {
    "CKF_TOKEN_PRESENT",
    "CKF_REMOVABLE_DEVICE",
    "CKF_HW_SLOT",
    "unknown token flag 0x00000008",
    "unknown token flag 0x00000010",
    "unknown token flag 0x00000020",
    "unknown token flag 0x00000040",
    "unknown token flag 0x00000080",
    "unknown token flag 0x00000100",
    "unknown token flag 0x00000200",
    "unknown token flag 0x00000400",
    "unknown token flag 0x00000800",
    "unknown token flag 0x00001000",
    "unknown token flag 0x00002000",
    "unknown token flag 0x00004000",
    "unknown token flag 0x00008000"
    "unknown token flag 0x00010000",
    "unknown token flag 0x00020000",
    "unknown token flag 0x00040000",
    "unknown token flag 0x00080000",
    "unknown token flag 0x00100000",
    "unknown token flag 0x00200000",
    "unknown token flag 0x00400000",
    "unknown token flag 0x00800000"
    "unknown token flag 0x01000000",
    "unknown token flag 0x02000000",
    "unknown token flag 0x04000000",
    "unknown token flag 0x08000000",
    "unknown token flag 0x10000000",
    "unknown token flag 0x20000000",
    "unknown token flag 0x40000000",
    "unknown token flag 0x80000000"
};

static const char *tokenFlagName[] = {
    "CKF_PKM_RNG",
    "CKF_WRITE_PROTECTED",
    "CKF_LOGIN_REQUIRED",
    "CKF_USER_PIN_INITIALIZED",
    "unknown token flag 0x00000010",
    "CKF_RESTORE_KEY_NOT_NEEDED",
    "CKF_CLOCK_ON_TOKEN",
    "unknown token flag 0x00000080",
    "CKF_PROTECTED_AUTHENTICATION_PATH",
    "CKF_DUAL_CRYPTO_OPERATIONS",
    "CKF_TOKEN_INITIALIZED",
    "CKF_SECONDARY_AUTHENTICATION",
    "unknown token flag 0x00001000",
    "unknown token flag 0x00002000",
    "unknown token flag 0x00004000",
    "unknown token flag 0x00008000",
    "CKF_USER_PIN_COUNT_LOW",
    "CKF_USER_PIN_FINAL_TRY",
    "CKF_USER_PIN_LOCKED",
    "CKF_USER_PIN_TO_BE_CHANGED",
    "CKF_SO_PIN_COUNT_LOW",
    "CKF_SO_PIN_FINAL_TRY",
    "CKF_SO_PIN_LOCKED",
    "CKF_SO_PIN_TO_BE_CHANGED",
    "unknown token flag 0x01000000",
    "unknown token flag 0x02000000",
    "unknown token flag 0x04000000",
    "unknown token flag 0x08000000",
    "unknown token flag 0x10000000",
    "unknown token flag 0x20000000",
    "unknown token flag 0x40000000",
    "unknown token flag 0x80000000"
};

static const unsigned char TLSClientRandom[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0d, 0x90, 0xbb, 0x5e, 0xc6, 0xe1, 0x3f, 0x71,
    0x0a, 0xa2, 0x70, 0x5a, 0x4f, 0xbc, 0x3f, 0x0d
};
static const unsigned char TLSServerRandom[] = {
    0x00, 0x00, 0x1d, 0x4a, 0x7a, 0x0a, 0xa5, 0x01,
    0x8e, 0x79, 0x72, 0xde, 0x9e, 0x2f, 0x8a, 0x0d,
    0xed, 0xb2, 0x5d, 0xf1, 0x14, 0xc2, 0xc6, 0x66,
    0x95, 0x86, 0xb0, 0x0d, 0x87, 0x2a, 0x2a, 0xc9
};

typedef enum {
    CORRECT,
    BOGUS_CLIENT_RANDOM,
    BOGUS_CLIENT_RANDOM_LEN,
    BOGUS_SERVER_RANDOM,
    BOGUS_SERVER_RANDOM_LEN
} enum_random_t;

void
dumpToHash64(const unsigned char *buf, unsigned int bufLen)
{
    unsigned int i;
    for (i = 0; i < bufLen; i += 8) {
        if (i % 32 == 0)
            printf("\n");
        printf(" 0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,",
               buf[i], buf[i + 1], buf[i + 2], buf[i + 3],
               buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]);
    }
    printf("\n");
}

#ifdef _WIN32
HMODULE hModule;
#else
PRLibrary *lib;
#endif

/*
* All api that belongs to pk11mode.c layer start with the prefix PKM_
*/
void PKM_LogIt(const char *fmt, ...);
void PKM_Error(const char *fmt, ...);
CK_SLOT_ID *PKM_GetSlotList(CK_FUNCTION_LIST_PTR pFunctionList,
                            CK_ULONG slotID);
CK_RV PKM_ShowInfo(CK_FUNCTION_LIST_PTR pFunctionList, CK_ULONG slotID);
CK_RV PKM_InitPWforDB(CK_FUNCTION_LIST_PTR pFunctionList,
                      CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                      CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen);
CK_RV PKM_Mechanism(CK_FUNCTION_LIST_PTR pFunctionList,
                    CK_SLOT_ID *pSlotList, CK_ULONG slotID);
CK_RV PKM_RNG(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID *pSlotList,
              CK_ULONG slotID);
CK_RV PKM_SessionLogin(CK_FUNCTION_LIST_PTR pFunctionList,
                       CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                       CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen);
CK_RV PKM_SecretKey(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID *pSlotList,
                    CK_ULONG slotID, CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen);
CK_RV PKM_PublicKey(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID *pSlotList,
                    CK_ULONG slotID, CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen);
CK_RV PKM_HybridMode(CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen,
                     CK_C_INITIALIZE_ARGS_NSS *initArgs);
CK_RV PKM_FindAllObjects(CK_FUNCTION_LIST_PTR pFunctionList,
                         CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                         CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen);
CK_RV PKM_MultiObjectManagement(CK_FUNCTION_LIST_PTR pFunctionList,
                                CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                                CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen);
CK_RV PKM_OperationalState(CK_FUNCTION_LIST_PTR pFunctionList,
                           CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                           CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen);
CK_RV PKM_LegacyFunctions(CK_FUNCTION_LIST_PTR pFunctionList,
                          CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                          CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen);
CK_RV PKM_AttributeCheck(CK_FUNCTION_LIST_PTR pFunctionList,
                         CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE obj,
                         CK_ATTRIBUTE_PTR expected_attrs,
                         CK_ULONG expected_attrs_count);
CK_RV PKM_MechCheck(CK_FUNCTION_LIST_PTR pFunctionList,
                    CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechType,
                    CK_FLAGS flags, CK_BBOOL check_sizes,
                    CK_ULONG minkeysize, CK_ULONG maxkeysize);
CK_RV PKM_TLSKeyAndMacDerive(CK_FUNCTION_LIST_PTR pFunctionList,
                             CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                             CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen,
                             CK_MECHANISM_TYPE mechType, enum_random_t rnd);
CK_RV PKM_TLSMasterKeyDerive(CK_FUNCTION_LIST_PTR pFunctionList,
                             CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                             CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen,
                             CK_MECHANISM_TYPE mechType,
                             enum_random_t rnd);
CK_RV PKM_KeyTests(CK_FUNCTION_LIST_PTR pFunctionList,
                   CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                   CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen);
CK_RV PKM_CSPTests(CK_FUNCTION_LIST_PTR pFunctionList,
                   CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                   CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen,
		   unsigned char *heap_top);
CK_RV PKM_DualFuncSign(CK_FUNCTION_LIST_PTR pFunctionList,
                       CK_SESSION_HANDLE hRwSession,
                       CK_OBJECT_HANDLE publicKey, CK_OBJECT_HANDLE privateKey,
                       CK_MECHANISM *sigMech, CK_OBJECT_HANDLE secretKey,
                       CK_MECHANISM *cryptMech,
                       const CK_BYTE *pData, CK_ULONG pDataLen);
CK_RV PKM_DualFuncDigest(CK_FUNCTION_LIST_PTR pFunctionList,
                         CK_SESSION_HANDLE hSession,
                         CK_OBJECT_HANDLE hSecKey, CK_MECHANISM *cryptMech,
                         CK_OBJECT_HANDLE hSecKeyDigest,
                         CK_MECHANISM *digestMech,
                         const CK_BYTE *pData, CK_ULONG pDataLen);
CK_RV PKM_PubKeySign(CK_FUNCTION_LIST_PTR pFunctionList,
                     CK_SESSION_HANDLE hRwSession,
                     CK_OBJECT_HANDLE hPubKey, CK_OBJECT_HANDLE hPrivKey,
                     CK_MECHANISM *signMech, const CK_BYTE *pData,
                     CK_ULONG dataLen);
CK_RV PKM_SecKeyCrypt(CK_FUNCTION_LIST_PTR pFunctionList,
                      CK_SESSION_HANDLE hSession,
                      CK_OBJECT_HANDLE hSymKey, CK_MECHANISM *cryptMech,
                      const CK_BYTE *pData, CK_ULONG dataLen);
CK_RV PKM_Hmac(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE sKey, CK_MECHANISM *hmacMech,
               const CK_BYTE *pData, CK_ULONG pDataLen);
CK_RV PKM_Digest(CK_FUNCTION_LIST_PTR pFunctionList,
                 CK_SESSION_HANDLE hRwSession,
                 CK_MECHANISM *digestMech, CK_OBJECT_HANDLE hSecretKey,
                 const CK_BYTE *pData, CK_ULONG pDataLen);
CK_RV PKM_WrapUnwrap(CK_FUNCTION_LIST_PTR pFunctionList,
                     CK_SESSION_HANDLE hSession,
                     CK_OBJECT_HANDLE hPublicKey,
                     CK_OBJECT_HANDLE hPrivateKey,
                     CK_MECHANISM *wrapMechanism,
                     CK_OBJECT_HANDLE hSecretKey,
                     CK_ATTRIBUTE *sKeyTemplate,
                     CK_ULONG skeyTempSize);
CK_RV PKM_RecoverFunctions(CK_FUNCTION_LIST_PTR pFunctionList,
                           CK_SESSION_HANDLE hSession,
                           CK_OBJECT_HANDLE hPubKey, CK_OBJECT_HANDLE hPrivKey,
                           CK_MECHANISM *signMech, const CK_BYTE *pData,
                           CK_ULONG pDataLen);
CK_RV PKM_ForkCheck(int expected, CK_FUNCTION_LIST_PTR fList,
                    PRBool forkAssert, CK_C_INITIALIZE_ARGS_NSS *initArgs);
CK_RV PKM_ErrorState(CK_FUNCTION_LIST_PTR pFunctionList, 
                     CK_SLOT_ID *pSlotList, CK_ULONG slotID,
		     CK_UTF8CHAR_PTR pw, CK_ULONG pwdLen,
                     CK_C_INITIALIZE_ARGS_NSS *initArgs);

/* Tools to manage library files */
CK_RV PKM_LoadLibrary(char *path);
void PKM_UnloadLibrary(void);
CK_RV PKM_GetFunctionList(const char *functionListName,
		 CK_FUNCTION_LIST_PTR *ppFunctionList);
char *PKM_GetLibraryPath(const void *addr);
CK_RV PKM_CopyFile(char *src, char *dest);
CK_RV PKM_MangleFile(char *file);
CK_RV PKM_LibraryIntegrityTests(char *path, CK_C_INITIALIZE_ARGS_NSS *initArgs);

void PKM_Help();
void PKM_CheckPath(char *string);
char *PKM_FilePasswd(char *pwFile);
static PRBool verbose = PR_FALSE;

int
main(int argc, char **argv)
{
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_RV crv = CKR_OK;
    CK_C_INITIALIZE_ARGS_NSS initArgs;
    CK_SLOT_ID *pSlotList = NULL;
    CK_TOKEN_INFO tokenInfo;
    CK_ULONG slotID = 0; /* slotID == 0 for FIPSMODE */
    const char *functionListName = "FC_GetFunctionList";
    const char *modeName = "FIPS";

    CK_UTF8CHAR *pwd = NULL;
    CK_ULONG pwdLen = 0;
    char *moduleSpec = NULL;
    char *configDir = NULL;
    char *dbPrefix = NULL;
    char *disableUnload = NULL;
    PRBool doForkTests = PR_TRUE;
    unsigned char *heap_top = sbrk(0);  /* record the top of the heap for latter scaning */

    PLOptStatus os;
    PLOptState *opt = PL_CreateOptState(argc, argv, "nvhf:Fd:p:");
    while (PL_OPT_EOL != (os = PL_GetNextOpt(opt))) {
        if (PL_OPT_BAD == os)
            continue;
        switch (opt->option) {
            case 'F': /* disable fork tests */
                doForkTests = PR_FALSE;
                break;
            case 'n': /* non fips mode */
                MODE = NONFIPSMODE;
                slotID = 1;
                break;
            case 'f': /* password file */
                pwd = (CK_UTF8CHAR *)PKM_FilePasswd((char *)opt->value);
                if (!pwd)
                    PKM_Help();
                break;
            case 'd': /* opt_CertDir */
                if (!opt->value)
                    PKM_Help();
                configDir = strdup(opt->value);
                PKM_CheckPath(configDir);
                break;
            case 'p': /* opt_DBPrefix */
                if (!opt->value)
                    PKM_Help();
                dbPrefix = strdup(opt->value);
                break;
            case 'v':
                verbose = PR_TRUE;
                break;
            case 'h': /* help message */
            default:
                PKM_Help();
                break;
        }
    }
    PL_DestroyOptState(opt);

    if (!pwd) {
        pwd = (CK_UTF8CHAR *)strdup("1Mozilla");
    }
    pwdLen = strlen((const char *)pwd);
    if (!configDir) {
        configDir = strdup("sql:.");
    }
    if (!dbPrefix) {
        dbPrefix = strdup("");
    }

    if (doForkTests) {
        /* first, try to fork without softoken loaded to make sure
         * everything is OK */
        crv = PKM_ForkCheck(123, NULL, PR_FALSE, NULL);
        if (crv != CKR_OK)
            goto cleanup;
    }

    crv = PKM_LoadLibrary(NULL);
    if (crv != CKR_OK) {
        PKM_Error("Failed to load library with 0x%08X, %-26s\n",  crv,
                  PKM_CK_RVtoStr(crv));
	goto cleanup;
    }

    if (MODE == FIPSMODE) {
	functionListName = "FC_GetFunctionList";
	modeName = "FIPS";
	
    } else {
	functionListName = "C_GetFunctionList";
	modeName = "NON FIPS";
    }
    crv = PKM_GetFunctionList(functionListName, &pFunctionList);
    if (crv != CKR_OK) {
        PKM_Error("%s failed with 0x%08X, %-26s\n", functionListName, crv,
                  PKM_CK_RVtoStr(crv));
	goto cleanup;
    }
    printf("Loaded %s for %s MODE; slotID %d \n",
               functionListName, modeName, (int)slotID);

    if (doForkTests) {
        /* now, try to fork with softoken loaded, but not initialized */
        crv = PKM_ForkCheck(CKR_CRYPTOKI_NOT_INITIALIZED, pFunctionList,
                            PR_TRUE, NULL);
        if (crv != CKR_OK)
            goto cleanup;
    }

    initArgs.CreateMutex = NULL;
    initArgs.DestroyMutex = NULL;
    initArgs.LockMutex = NULL;
    initArgs.UnlockMutex = NULL;
    initArgs.flags = CKF_OS_LOCKING_OK;
    moduleSpec = PR_smprintf("configdir='%s' certPrefix='%s' "
                             "keyPrefix='%s' secmod='secmod.db' flags= ",
                             configDir, dbPrefix, dbPrefix);
    initArgs.LibraryParameters = (CK_CHAR_PTR *)moduleSpec;
    initArgs.pReserved = NULL;

    /*DebugBreak();*/
    /* FIPSMODE invokes FC_Initialize as pFunctionList->C_Initialize */
    /* NSS cryptographic module library initialization for the FIPS  */
    /* Approved mode when FC_Initialize is envoked will perfom       */
    /* software integrity test, and power-up self-tests before       */
    /* FC_Initialize returns                                         */
    crv = pFunctionList->C_Initialize(&initArgs);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Initialize succeeded\n");
    } else {
        PKM_Error("C_Initialize failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }

    if (doForkTests) {
        /* Disable core on fork for this test, since we are testing the
         * pathological case, and if enabled, the child process would dump
         * core in C_GetTokenInfo .
         * We can still differentiate the correct from incorrect behavior
         * by the PKCS#11 return code.
         */
        /* try to fork with softoken both loaded and initialized */
        crv = PKM_ForkCheck(CKR_DEVICE_ERROR, pFunctionList, PR_FALSE, NULL);
        if (crv != CKR_OK)
            goto cleanup;
    }

    if (doForkTests) {
        /* In this next test, we fork and try to re-initialize softoken in
         * the child. This should now work because softoken has the ability
         * to hard reset.
         */
        /* try to fork with softoken both loaded and initialized */
        crv = PKM_ForkCheck(CKR_OK, pFunctionList, PR_TRUE, &initArgs);
        if (crv != CKR_OK)
            goto cleanup;
    }

    crv = PKM_ShowInfo(pFunctionList, slotID);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_ShowInfo succeeded\n");
    } else {
        PKM_Error("PKM_ShowInfo failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }
    pSlotList = PKM_GetSlotList(pFunctionList, slotID);
    if (pSlotList == NULL) {
        PKM_Error("PKM_GetSlotList failed with \n");
        goto cleanup;
    }
    crv = pFunctionList->C_GetTokenInfo(pSlotList[slotID], &tokenInfo);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GetTokenInfo succeeded\n\n");
    } else {
        PKM_Error("C_GetTokenInfo failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }

    if (!(tokenInfo.flags & CKF_USER_PIN_INITIALIZED)) {
        crv = PKM_InitPWforDB(pFunctionList, pSlotList, slotID,
                              pwd, pwdLen);
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_InitPWforDB succeeded\n\n");
        } else {
            PKM_Error("PKM_InitPWforDB failed with 0x%08X, %-26s\n", crv,
                      PKM_CK_RVtoStr(crv));
            goto cleanup;
        }
    } else {
        PKM_LogIt("using existing DB\n");
    }

    /* general mechanism by token */
    crv = PKM_Mechanism(pFunctionList, pSlotList, slotID);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_Mechanism succeeded\n\n");
    } else {
        PKM_Error("PKM_Mechanism failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }
    /* RNG example without Login */
    crv = PKM_RNG(pFunctionList, pSlotList, slotID);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_RNG succeeded\n\n");
    } else {
        PKM_Error("PKM_RNG failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }

    crv = PKM_SessionLogin(pFunctionList, pSlotList, slotID,
                           pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_SessionLogin succeeded\n\n");
    } else {
        PKM_Error("PKM_SessionLogin failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }

    /*
     * PKM_KeyTest creates RSA,DSA public keys
     * and AES, DES3 secret keys.
     * then does digest, hmac, encrypt/decrypt, signing operations.
     */
    crv = PKM_KeyTests(pFunctionList, pSlotList, slotID,
                       pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_KeyTests succeeded\n\n");
    } else {
        PKM_Error("PKM_KeyTest failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }

    crv = PKM_SecretKey(pFunctionList, pSlotList, slotID, pwd,
                        pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_SecretKey succeeded\n\n");
    } else {
        PKM_Error("PKM_SecretKey failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }

    crv = PKM_PublicKey(pFunctionList, pSlotList, slotID,
                        pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_PublicKey succeeded\n\n");
    } else {
        PKM_Error("PKM_PublicKey failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }
    crv = PKM_OperationalState(pFunctionList, pSlotList, slotID,
                               pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_OperationalState succeeded\n\n");
    } else {
        PKM_Error("PKM_OperationalState failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }
    crv = PKM_MultiObjectManagement(pFunctionList, pSlotList, slotID,
                                    pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_MultiObjectManagement succeeded\n\n");
    } else {
        PKM_Error("PKM_MultiObjectManagement failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }
    crv = PKM_LegacyFunctions(pFunctionList, pSlotList, slotID,
                              pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_LegacyFunctions succeeded\n\n");
    } else {
        PKM_Error("PKM_LegacyFunctions failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }
    crv = PKM_TLSKeyAndMacDerive(pFunctionList, pSlotList, slotID,
                                 pwd, pwdLen,
                                 CKM_TLS_KEY_AND_MAC_DERIVE, CORRECT);

    if (crv == CKR_OK) {
        PKM_LogIt("PKM_TLSKeyAndMacDerive succeeded\n\n");
    } else {
        PKM_Error("PKM_TLSKeyAndMacDerive failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }
    crv = PKM_TLSMasterKeyDerive(pFunctionList, pSlotList, slotID,
                                 pwd, pwdLen,
                                 CKM_TLS_MASTER_KEY_DERIVE,
                                 CORRECT);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_TLSMasterKeyDerive succeeded\n\n");
    } else {
        PKM_Error("PKM_TLSMasterKeyDerive failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }
    crv = PKM_TLSMasterKeyDerive(pFunctionList, pSlotList, slotID,
                                 pwd, pwdLen,
                                 CKM_TLS_MASTER_KEY_DERIVE_DH,
                                 CORRECT);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_TLSMasterKeyDerive succeeded\n\n");
    } else {
        PKM_Error("PKM_TLSMasterKeyDerive failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }
    crv = PKM_FindAllObjects(pFunctionList, pSlotList, slotID,
                             pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_FindAllObjects succeeded\n\n");
    } else {
        PKM_Error("PKM_FindAllObjects failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }
    crv = PKM_CSPTests(pFunctionList, pSlotList, slotID, pwd, pwdLen, heap_top);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_CSPTests succeeded\n\n");
    } else {
        PKM_Error("PKM_CSPTests failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }

    crv = PKM_ErrorState(pFunctionList, pSlotList, slotID, 
			 pwd, pwdLen, &initArgs);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_ErrorState succeeded\n\n");
    } else {
        PKM_Error("PKM_ErrorState failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }

    crv = pFunctionList->C_Finalize(NULL);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Finalize succeeded\n\n");
    } else {
        PKM_Error("C_Finalize failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }

    if (doForkTests) {
        /* try to fork with softoken still loaded, but de-initialized */
        crv = PKM_ForkCheck(CKR_CRYPTOKI_NOT_INITIALIZED, pFunctionList,
                            PR_TRUE, NULL);
        if (crv != CKR_OK)
            goto cleanup;
    }

    free(pSlotList);

    /* demonstrate how an application can be in Hybrid mode */
    /* PKM_HybridMode shows how to switch between NONFIPS */
    /* mode to FIPS mode */

    PKM_LogIt("Testing Hybrid mode \n");
    crv = PKM_HybridMode(pwd, pwdLen, &initArgs);
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_HybridMode succeeded\n");
    } else {
        PKM_Error("PKM_HybridMode failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        goto cleanup;
    }

    if (doForkTests) {
        /* testing one more C_Initialize / C_Finalize to exercise getpid()
         * fork check code */
        crv = pFunctionList->C_Initialize(&initArgs);
        if (crv == CKR_OK) {
            PKM_LogIt("C_Initialize succeeded\n");
        } else {
            PKM_Error("C_Initialize failed with 0x%08X, %-26s\n", crv,
                      PKM_CK_RVtoStr(crv));
            goto cleanup;
        }
        crv = pFunctionList->C_Finalize(NULL);
        if (crv == CKR_OK) {
            PKM_LogIt("C_Finalize succeeded\n");
        } else {
            PKM_Error("C_Finalize failed with 0x%08X, %-26s\n", crv,
                      PKM_CK_RVtoStr(crv));
            goto cleanup;
        }
        /* try to C_Initialize / C_Finalize in child. This should succeed */
        crv = PKM_ForkCheck(CKR_OK, pFunctionList, PR_TRUE, &initArgs);
    }
    if (MODE == FIPSMODE) {
	/* get our library names for the next steps */
	char *libraryPath = PKM_GetLibraryPath(pFunctionList);
	if (crv != CKR_OK) {
	    goto cleanup;
	}

	crv = PKM_LibraryIntegrityTests(libraryPath, &initArgs);
	PR_Free(libraryPath);
	if (crv == CKR_OK) {
            PKM_LogIt("PKM_LibraryIntegrityTests succeeded\n");
	} else {
            PKM_Error("PKM_LibraryIntegrityTests failed with 0x%08X, %-26s\n",			  crv, PKM_CK_RVtoStr(crv));
            goto cleanup;
	}
    }

    PKM_LogIt("unloading NSS PKCS # 11 softoken and exiting\n");
cleanup:

    if (pwd) {
        free(pwd);
    }
    if (configDir) {
        free(configDir);
    }
    if (dbPrefix) {
        free(dbPrefix);
    }
    if (moduleSpec) {
        PR_smprintf_free(moduleSpec);
    }

    disableUnload = PR_GetEnvSecure("NSS_DISABLE_UNLOAD");
    if (!disableUnload) {
        PR_UnloadLibrary(lib);
	lib = NULL;
    }

    if (CKR_OK == crv && doForkTests && !disableUnload) {
        /* try to fork with softoken both de-initialized and unloaded */
        crv = PKM_ForkCheck(123, NULL, PR_TRUE, NULL);
    }

    printf("**** Total number of TESTS ran in %s is %d. ****\n",
           ((MODE == FIPSMODE) ? "FIPS MODE" : "NON FIPS MODE"), (int)NUMTESTS);
    if (CKR_OK == crv) {
        printf("**** ALL TESTS PASSED ****\n");
    }

    return crv;
}


CK_RV
PKM_LoadLibrary(char *path)
{
#ifdef _WIN32
    hModule = LoadLibrary(LIB_NAME);
    if (hModule == NULL) {
        PKM_Error("cannot load %s\n", LIB_NAME);
        return CKR_DEVICE_ERROR;
    }
#else
    {
        char *libname = NULL;
        char *newLibname = NULL;
        /* Get the platform-dependent library name of the NSS 
         * cryptographic module */
        libname = PR_GetLibraryName(NULL, "softokn3");
	if (libname == NULL) {
	    return CKR_DEVICE_ERROR;
	}
	if (path) {
	    int pathLen, nameLen;

	    pathLen=strlen(path);
	    nameLen=strlen(libname);
	    newLibname = malloc(pathLen+nameLen+1);
	    if (newLibname == NULL) {
		PR_FreeLibraryName(libname);
		return CKR_HOST_MEMORY;
	    }
	    memcpy(newLibname, path, pathLen);
	    memcpy(&newLibname[pathLen], libname, nameLen);
	    newLibname[pathLen+nameLen] = 0;
	}
        lib = PR_LoadLibrary(newLibname ? newLibname : libname);
        PR_FreeLibraryName(libname);
	if (newLibname) free(newLibname);
	if (lib == NULL) {
	    return CKR_DEVICE_ERROR;
	}
    }
#endif
    return CKR_OK;
}

void
PKM_UnloadLibrary(void)
{
#ifdef _WIN32
    FreeLibrary(hModule);
    hModule = NULL;
#else
    PR_UnloadLibrary(lib);
    lib = NULL;
#endif
}

CK_RV
PKM_GetFunctionList(const char *functionListName,
		 CK_FUNCTION_LIST_PTR *ppFunctionList)
{
    CK_C_GetFunctionList pC_GetFunctionList;
#ifdef _WIN32
    pC_GetFunctionList = (CK_C_GetFunctionList)
        GetProcAddress(hModule, functionListName);
#else
    pC_GetFunctionList = (CK_C_GetFunctionList)PR_FindFunctionSymbol(lib,
				functionListName);
#endif
    if (pC_GetFunctionList == NULL) {
	return CKR_DEVICE_ERROR;
    }
    return (*pC_GetFunctionList)(ppFunctionList);
}

char *PKM_GetLibraryPath(const void *addr)
{
    int libNameLen, fullPathLen;
    char *softokenLibName = PR_GetLibraryName(NULL,"softokn3");
    char *softokenLibPath;
    if (softokenLibName == NULL) {
	return NULL;
    }
    libNameLen = strlen(softokenLibName);
    softokenLibPath = PR_GetLibraryFilePathname(softokenLibName, addr);
    PR_FreeLibraryName(softokenLibName);
    if (softokenLibPath == NULL) {
	return NULL;
    }
    fullPathLen = strlen(softokenLibPath);
    if (libNameLen > fullPathLen ){
	PR_Free(softokenLibPath);
	return NULL;
    }
    /* truncate the actual softoken name */
    softokenLibPath[fullPathLen-libNameLen] = 0;
    return softokenLibPath;
}
    

CK_RV 
PKM_CopyFile(char *src, char *dest)
{
    int fsrc, fdest;
    char buf[4096];
    struct stat statbuf;
    size_t bytes_in, bytes_out;
    int rv;

    fsrc = open(src, O_RDONLY);
    if (fsrc < 0) {
	perror(src);
	return CKR_DEVICE_ERROR;
    }

    rv = fstat(fsrc, &statbuf);
    if (rv < 0) {
	perror(src);
	close(fsrc);
	return CKR_DEVICE_ERROR;
    }
    if (!S_ISREG(statbuf.st_mode)) {
	fprintf(stderr,"copy: %s is not a regular file\n",src);
	close(fsrc);
	return CKR_DEVICE_ERROR;
    }
    fdest = open(dest, O_WRONLY|O_CREAT|O_TRUNC, statbuf.st_mode & 0777);
    if (fdest <0 ) {
	perror(dest);
	close(fsrc);
	return CKR_DEVICE_ERROR;
    }

     while ((bytes_in = read(fsrc, buf, sizeof(buf))) > 0) {
	bytes_out = write(fdest, buf, bytes_in);
	if (bytes_out != bytes_in) {
	    fprintf(stderr,"copy: Short write from %s to %s\n", src, dest);
	    break;
	}
     }
     if (bytes_in < 0) {
	perror(src);
     }
     close(fsrc);
     close(fdest);
     return bytes_in == 0 ? CKR_OK: CKR_DEVICE_ERROR;
}

CK_RV 
PKM_MangleFile(char *file)
{
    int fd;
    char b;
    size_t bytes;

    fd = open(file,O_RDWR);
    if (fd < 0) {
	perror(file);
	return CKR_DEVICE_ERROR;
    }
    lseek(fd,-1,SEEK_END);
    bytes = read(fd, &b, 1);
    if (bytes != 1) {
	fprintf(stderr,"mangle:Failed to read %s \n",file);
	close(fd);
	return CKR_DEVICE_ERROR;
    }
    b = b ^ 0x1;
    lseek(fd,-1,SEEK_END);
    bytes = write(fd,&b,1);
    if (bytes != 1) {
	fprintf(stderr,"mangle:Failed to write %s \n",file);
	close(fd);
	return CKR_DEVICE_ERROR;
    }
    return CKR_OK;
}
	
CK_RV
PKM_MangleLibrary(char *lib)
{
    char *libname = NULL;
    CK_RV crv;

    libname = PR_GetLibraryName(NULL,lib);
    if (libname == NULL) {
	crv = CKR_HOST_MEMORY;
	goto cleanup;
    }
    crv = PKM_MangleFile(libname);
cleanup:
    PR_FreeLibraryName(libname);
    return crv;
}

CK_RV 
PKM_UnMangleLibrary(char *lib)
{
    /* it's just a toggle */
    return PKM_MangleLibrary(lib);
}


CK_RV PKM_LoadInit(CK_C_INITIALIZE_ARGS_NSS *initArgs,
		   PRBool expectFailure, char *testname)
{ 
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_RV crv;

    crv = PKM_LoadLibrary("./");
    if (crv != CKR_OK) {
        PKM_Error("Couldn't load the library for %s, 0x08X, %-26s\n",
			 testname, crv, PKM_CK_RVtoStr(crv));
	return crv;
    }
    crv = PKM_GetFunctionList("FC_GetFunctionList", &pFunctionList);
    if (pFunctionList == NULL) {
        PKM_Error("Couldn't get the function list for %s, 0x%08X, %-26s\n",
			 testname, crv, PKM_CK_RVtoStr(crv));
	return crv;
    }
    crv = pFunctionList->C_Initialize(initArgs);
    if (crv == CKR_OK) {
	if (expectFailure) {
            PKM_Error("C_Initialize incorrectly succeeded for %s\n", testname);
	    crv = CKR_DEVICE_ERROR;
	} else {
            PKM_LogIt("C_Initialize succeeded for %s\n", testname);
	}
        pFunctionList->C_Finalize(NULL);
    } else {
	if (expectFailure) {
            PKM_LogIt("C_Initialize correctly failed for %s with 0x%08X,"
		      " %-26s\n", testname, crv, PKM_CK_RVtoStr(crv));
	    crv = CKR_OK;
	} else {
            PKM_Error("C_Initialize failed for %s with 0x%08X, %-26s\n", 
		      testname, crv, PKM_CK_RVtoStr(crv));
	}
    }
    PKM_UnloadLibrary();
    return crv;
}

#define CHK "chk"
CK_RV
PKM_CopyLibrary(char *library, char *source, char *dest)
{
    char *libname = NULL;
    char *sbuf = NULL,*dbuf = NULL;
    char *extension;
    size_t libLen, sLen, dLen;
    size_t sbufLen, dbufLen;
    CK_RV crv = CKR_OK;
    size_t offset;

    sLen = strlen(source);
    dLen = strlen(dest);

    libname = PR_GetLibraryName(NULL,library);
    if (libname == NULL) {
	crv = CKR_HOST_MEMORY;
	goto cleanup;
    }
    libLen = strlen(libname);
    sbufLen = libLen+sLen+sizeof(CHK);
    sbuf = malloc(sbufLen);
    if (sbuf == NULL) {
	crv = CKR_HOST_MEMORY;
	goto cleanup;
    }
    dbufLen = libLen+dLen+sizeof(CHK);
    dbuf = malloc(dbufLen);
    if (dbuf == NULL) {
	crv = CKR_HOST_MEMORY;
	goto cleanup;
    }
    memcpy(sbuf, source, sLen);
    memcpy(&sbuf[sLen],libname,libLen);
    sbuf[sLen+libLen] = 0;
    memcpy(dbuf, dest, dLen);
    memcpy(&dbuf[dLen],libname,libLen);
    dbuf[dLen+libLen] = 0;

    crv = PKM_CopyFile(sbuf,dbuf);
    if (crv != CKR_OK) {
	goto cleanup;
    }
    extension = strrchr(libname,'.');
    if (extension == NULL) {
	crv = CKR_DEVICE_ERROR;
	goto cleanup;
    }
    offset = extension-libname+1;
    memcpy(&sbuf[sLen+offset],CHK, sizeof(CHK));
    memcpy(&dbuf[dLen+offset],CHK, sizeof(CHK));
    crv = PKM_CopyFile(sbuf,dbuf);
    if (crv != CKR_OK) {
	goto cleanup;
    }
cleanup:
    free(dbuf);
    free(sbuf);
    if (libname) {
        PR_FreeLibraryName(libname);
    }
    return crv;
}

CK_RV PKM_LibraryIntegrityTests(char *path, CK_C_INITIALIZE_ARGS_NSS *initArgs)
{
    CK_RV crv;

    PKM_LogIt("PKM_LibraryIntegrityTests started\n");
    NUMTESTS++; /* increment NUMTESTS */

    PKM_UnloadLibrary();
    crv = PKM_CopyLibrary("softokn3",path,"./");
    if (crv != CKR_OK) {
        PKM_Error("PKM_LibraryIntegrityTests couldn't copy softokn3"
                  " libraries\n");
	return crv;
    }
    crv = PKM_CopyLibrary("freeblpriv3",path,"./");
    if (crv != CKR_OK) {
        PKM_Error("PKM_LibraryIntegrityTests couldn't copy freeblpriv3"
                  " libraries\n");
	return crv;
    }
    crv = PKM_CopyLibrary("nssdbm3",path,"./");
    if (crv != CKR_OK) {
        PKM_Error("PKM_LibraryIntegrityTests couldn't copy nssdb3"
                  " libraries\n");
	return crv;
    }

    crv =  PKM_MangleLibrary("softokn3");
    if (crv != CKR_OK) {
        PKM_Error("PKM_LibraryIntegrityTests couldn't mangle softokn3"
                  " libraries\n");
	return crv;
    }

    crv = PKM_LoadInit(initArgs, PR_TRUE, "softokn3 mangled");
    if (crv != CKR_OK) {
	return crv;
    }
    crv =  PKM_UnMangleLibrary("softokn3");
    if (crv != CKR_OK) {
        PKM_Error("PKM_LibraryIntegrityTests couldn't unmangle softokn3"
                  " libraries\n");
	return crv;
    }
    return CKR_OK;
}
   
/*
*  PKM_KeyTests
*
*
*/

CK_RV
PKM_KeyTests(CK_FUNCTION_LIST_PTR pFunctionList,
             CK_SLOT_ID *pSlotList, CK_ULONG slotID,
             CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen)
{
    CK_SESSION_HANDLE hRwSession;

    CK_RV crv = CKR_OK;

    /*** DSA Key ***/
    CK_MECHANISM dsaParamGenMech;
    CK_ULONG primeBits = DSA_BITS;
    CK_ULONG subPrimeBits = DSA_SUB_PRIME_BITS;
    CK_ULONG seedBits = DSA_SUB_PRIME_BITS;
    CK_ATTRIBUTE dsaParamGenTemplate[3];
    CK_OBJECT_HANDLE hDsaParams = CK_INVALID_HANDLE;
    CK_BYTE DSA_P[DSA_BITS/8];
    CK_BYTE DSA_Q[DSA_SUB_PRIME_BITS/8];
    CK_BYTE DSA_G[DSA_BITS/8];
    CK_MECHANISM dsaKeyPairGenMech;
    CK_ATTRIBUTE dsaPubKeyTemplate[5];
    CK_ATTRIBUTE dsaPrivKeyTemplate[5];
    CK_OBJECT_HANDLE hDSApubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hDSAprivKey = CK_INVALID_HANDLE;

    /**** RSA Key ***/
    CK_KEY_TYPE rsatype = CKK_RSA;
    CK_MECHANISM rsaKeyPairGenMech;
    CK_BYTE subject[] = { "RSA Private Key" };
    CK_ULONG modulusBits = RSA_BITS;
    CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
    CK_BYTE id[] = { "RSA123" };
    CK_ATTRIBUTE rsaPubKeyTemplate[9];
    CK_ATTRIBUTE rsaPrivKeyTemplate[11];
    CK_ATTRIBUTE rsaPrivValueTemplate[6];
    CK_OBJECT_HANDLE hRSApubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hRSAprivKey = CK_INVALID_HANDLE;
    CK_BYTE RSA_PRIME_1[RSA_BITS/16];
    CK_BYTE RSA_PRIME_2[RSA_BITS/16];
    CK_BYTE RSA_PRIVATE_EXPONENT[RSA_BITS/8];
    CK_BYTE RSA_EXPONENT_1[RSA_BITS/16];
    CK_BYTE RSA_EXPONENT_2[RSA_BITS/16];
    CK_BYTE RSA_COEFFICIENT[RSA_BITS/16];
    CK_BYTE SECRET_VALUE[DSA_BITS/8];

    /*** AES Key ***/
    CK_MECHANISM sAESKeyMech = {
        CKM_AES_KEY_GEN, NULL, 0
    };
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE keyAESType = CKK_AES;
    CK_UTF8CHAR AESlabel[] = "An AES secret key object";
    CK_ULONG AESvalueLen = 32;
    CK_ATTRIBUTE sAESKeyTemplate[9];
    CK_OBJECT_HANDLE hAESSecKey;

    CK_ATTRIBUTE secretValueTemplate[1];

    /*** DES3 Key ***/
    CK_KEY_TYPE keyDES3Type = CKK_DES3;
    CK_UTF8CHAR DES3label[] = "An Triple DES secret key object";
    CK_ULONG DES3valueLen = 56;
    CK_MECHANISM sDES3KeyGenMechanism = {
        CKM_DES3_KEY_GEN, NULL, 0
    };
    CK_ATTRIBUTE sDES3KeyTemplate[9];
    CK_OBJECT_HANDLE hDES3SecKey;

    CK_MECHANISM dsaWithSha1Mech = {
        CKM_DSA_SHA1, NULL, 0
    };

    CK_BYTE IV[16];
    CK_MECHANISM mech_DES3_CBC;
    CK_MECHANISM mech_DES3_CBC_PAD;
    CK_MECHANISM mech_AES_CBC_PAD;
    CK_MECHANISM mech_AES_CBC;
    struct mech_str {
        CK_ULONG mechanism;
        const char *mechanismStr;
    };

    typedef struct mech_str mech_str;

    mech_str digestMechs[] = {
        { CKM_SHA_1, "CKM_SHA_1 " },
        { CKM_SHA224, "CKM_SHA224" },
        { CKM_SHA256, "CKM_SHA256" },
        { CKM_SHA384, "CKM_SHA384" },
        { CKM_SHA512, "CKM_SHA512" }
    };
    mech_str hmacMechs[] = {
        { CKM_SHA_1_HMAC, "CKM_SHA_1_HMAC" },
        { CKM_SHA224_HMAC, "CKM_SHA224_HMAC" },
        { CKM_SHA256_HMAC, "CKM_SHA256_HMAC" },
        { CKM_SHA384_HMAC, "CKM_SHA384_HMAC" },
        { CKM_SHA512_HMAC, "CKM_SHA512_HMAC" }
    };
    mech_str sigRSAMechs[] = {
        { CKM_SHA1_RSA_PKCS, "CKM_SHA1_RSA_PKCS" },
        { CKM_SHA224_RSA_PKCS, "CKM_SHA224_RSA_PKCS" },
        { CKM_SHA256_RSA_PKCS, "CKM_SHA256_RSA_PKCS" },
        { CKM_SHA384_RSA_PKCS, "CKM_SHA384_RSA_PKCS" },
        { CKM_SHA512_RSA_PKCS, "CKM_SHA512_RSA_PKCS" }
    };

    CK_ULONG digestMechsSZ = NUM_ELEM(digestMechs);
    CK_ULONG sigRSAMechsSZ = NUM_ELEM(sigRSAMechs);
    CK_ULONG hmacMechsSZ = NUM_ELEM(hmacMechs);
    CK_MECHANISM mech;

    unsigned int i;

    PKM_LogIt("PKM_KeyTests started\n");
    NUMTESTS++; /* increment NUMTESTS */

    /* DSA key init */
    dsaParamGenMech.mechanism = CKM_DSA_PARAMETER_GEN;
    dsaParamGenMech.pParameter = NULL_PTR;
    dsaParamGenMech.ulParameterLen = 0;
    dsaParamGenTemplate[0].type = CKA_PRIME_BITS;
    dsaParamGenTemplate[0].pValue = &primeBits;
    dsaParamGenTemplate[0].ulValueLen = sizeof(primeBits);
    dsaParamGenTemplate[1].type = CKA_SUB_PRIME_BITS;
    dsaParamGenTemplate[1].pValue = &subPrimeBits;
    dsaParamGenTemplate[1].ulValueLen = sizeof(subPrimeBits);
    dsaParamGenTemplate[2].type = CKA_NSS_PQG_SEED_BITS;
    dsaParamGenTemplate[2].pValue = &seedBits;
    dsaParamGenTemplate[2].ulValueLen = sizeof(seedBits);
    dsaPubKeyTemplate[0].type = CKA_PRIME;
    dsaPubKeyTemplate[0].pValue = DSA_P;
    dsaPubKeyTemplate[0].ulValueLen = sizeof(DSA_P);
    dsaPubKeyTemplate[1].type = CKA_SUBPRIME;
    dsaPubKeyTemplate[1].pValue = DSA_Q;
    dsaPubKeyTemplate[1].ulValueLen = sizeof(DSA_Q);
    dsaPubKeyTemplate[2].type = CKA_BASE;
    dsaPubKeyTemplate[2].pValue = DSA_G;
    dsaPubKeyTemplate[2].ulValueLen = sizeof(DSA_G);
    dsaPubKeyTemplate[3].type = CKA_TOKEN;
    dsaPubKeyTemplate[3].pValue = &true;
    dsaPubKeyTemplate[3].ulValueLen = sizeof(true);
    dsaPubKeyTemplate[4].type = CKA_VERIFY;
    dsaPubKeyTemplate[4].pValue = &true;
    dsaPubKeyTemplate[4].ulValueLen = sizeof(true);
    dsaKeyPairGenMech.mechanism = CKM_DSA_KEY_PAIR_GEN;
    dsaKeyPairGenMech.pParameter = NULL_PTR;
    dsaKeyPairGenMech.ulParameterLen = 0;
    dsaPrivKeyTemplate[0].type = CKA_TOKEN;
    dsaPrivKeyTemplate[0].pValue = &true;
    dsaPrivKeyTemplate[0].ulValueLen = sizeof(true);
    dsaPrivKeyTemplate[1].type = CKA_PRIVATE;
    dsaPrivKeyTemplate[1].pValue = &true;
    dsaPrivKeyTemplate[1].ulValueLen = sizeof(true);
    dsaPrivKeyTemplate[2].type = CKA_SENSITIVE;
    dsaPrivKeyTemplate[2].pValue = &true;
    dsaPrivKeyTemplate[2].ulValueLen = sizeof(true);
    dsaPrivKeyTemplate[3].type = CKA_SIGN,
    dsaPrivKeyTemplate[3].pValue = &true;
    dsaPrivKeyTemplate[3].ulValueLen = sizeof(true);
    dsaPrivKeyTemplate[4].type = CKA_EXTRACTABLE;
    dsaPrivKeyTemplate[4].pValue = &true;
    dsaPrivKeyTemplate[4].ulValueLen = sizeof(true);

    /* RSA key init */
    rsaKeyPairGenMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    rsaKeyPairGenMech.pParameter = NULL_PTR;
    rsaKeyPairGenMech.ulParameterLen = 0;

    rsaPubKeyTemplate[0].type = CKA_KEY_TYPE;
    rsaPubKeyTemplate[0].pValue = &rsatype;
    rsaPubKeyTemplate[0].ulValueLen = sizeof(rsatype);
    rsaPubKeyTemplate[1].type = CKA_PRIVATE;
    rsaPubKeyTemplate[1].pValue = &true;
    rsaPubKeyTemplate[1].ulValueLen = sizeof(true);
    rsaPubKeyTemplate[2].type = CKA_ENCRYPT;
    rsaPubKeyTemplate[2].pValue = &true;
    rsaPubKeyTemplate[2].ulValueLen = sizeof(true);
    rsaPubKeyTemplate[3].type = CKA_DECRYPT;
    rsaPubKeyTemplate[3].pValue = &true;
    rsaPubKeyTemplate[3].ulValueLen = sizeof(true);
    rsaPubKeyTemplate[4].type = CKA_VERIFY;
    rsaPubKeyTemplate[4].pValue = &true;
    rsaPubKeyTemplate[4].ulValueLen = sizeof(true);
    rsaPubKeyTemplate[5].type = CKA_SIGN;
    rsaPubKeyTemplate[5].pValue = &true;
    rsaPubKeyTemplate[5].ulValueLen = sizeof(true);
    rsaPubKeyTemplate[6].type = CKA_WRAP;
    rsaPubKeyTemplate[6].pValue = &true;
    rsaPubKeyTemplate[6].ulValueLen = sizeof(true);
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
    rsaPrivKeyTemplate[1].pValue = &true;
    rsaPrivKeyTemplate[1].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[2].type = CKA_PRIVATE;
    rsaPrivKeyTemplate[2].pValue = &true;
    rsaPrivKeyTemplate[2].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[3].type = CKA_SUBJECT;
    rsaPrivKeyTemplate[3].pValue = subject;
    rsaPrivKeyTemplate[3].ulValueLen = sizeof(subject);
    rsaPrivKeyTemplate[4].type = CKA_ID;
    rsaPrivKeyTemplate[4].pValue = id;
    rsaPrivKeyTemplate[4].ulValueLen = sizeof(id);
    rsaPrivKeyTemplate[5].type = CKA_SENSITIVE;
    rsaPrivKeyTemplate[5].pValue = &true;
    rsaPrivKeyTemplate[5].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[6].type = CKA_ENCRYPT;
    rsaPrivKeyTemplate[6].pValue = &true;
    rsaPrivKeyTemplate[6].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[7].type = CKA_DECRYPT;
    rsaPrivKeyTemplate[7].pValue = &true;
    rsaPrivKeyTemplate[7].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[8].type = CKA_VERIFY;
    rsaPrivKeyTemplate[8].pValue = &true;
    rsaPrivKeyTemplate[8].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[9].type = CKA_SIGN;
    rsaPrivKeyTemplate[9].pValue = &true;
    rsaPrivKeyTemplate[9].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[10].type = CKA_UNWRAP;
    rsaPrivKeyTemplate[10].pValue = &true;
    rsaPrivKeyTemplate[10].ulValueLen = sizeof(true);

    rsaPrivValueTemplate[0].type = CKA_PRIVATE_EXPONENT;
    rsaPrivValueTemplate[0].pValue = RSA_PRIVATE_EXPONENT;
    rsaPrivValueTemplate[0].ulValueLen = sizeof(RSA_PRIVATE_EXPONENT);
    rsaPrivValueTemplate[1].type = CKA_PRIME_1;
    rsaPrivValueTemplate[1].pValue = RSA_PRIME_1;
    rsaPrivValueTemplate[1].ulValueLen = sizeof(RSA_PRIME_1);
    rsaPrivValueTemplate[2].type = CKA_PRIME_2;
    rsaPrivValueTemplate[2].pValue = RSA_PRIME_2;
    rsaPrivValueTemplate[2].ulValueLen = sizeof(RSA_PRIME_1);
    rsaPrivValueTemplate[3].type = CKA_EXPONENT_1;
    rsaPrivValueTemplate[3].pValue = RSA_EXPONENT_1;
    rsaPrivValueTemplate[3].ulValueLen = sizeof(RSA_EXPONENT_1);
    rsaPrivValueTemplate[4].type = CKA_EXPONENT_2;
    rsaPrivValueTemplate[4].pValue = RSA_EXPONENT_2;
    rsaPrivValueTemplate[4].ulValueLen = sizeof(RSA_EXPONENT_2);
    rsaPrivValueTemplate[5].type = CKA_COEFFICIENT;
    rsaPrivValueTemplate[5].pValue = RSA_COEFFICIENT;
    rsaPrivValueTemplate[5].ulValueLen = sizeof(RSA_COEFFICIENT);

    /* AES key template */
    sAESKeyTemplate[0].type = CKA_CLASS;
    sAESKeyTemplate[0].pValue = &class;
    sAESKeyTemplate[0].ulValueLen = sizeof(class);
    sAESKeyTemplate[1].type = CKA_KEY_TYPE;
    sAESKeyTemplate[1].pValue = &keyAESType;
    sAESKeyTemplate[1].ulValueLen = sizeof(keyAESType);
    sAESKeyTemplate[2].type = CKA_LABEL;
    sAESKeyTemplate[2].pValue = AESlabel;
    sAESKeyTemplate[2].ulValueLen = sizeof(AESlabel) - 1;
    sAESKeyTemplate[3].type = CKA_ENCRYPT;
    sAESKeyTemplate[3].pValue = &true;
    sAESKeyTemplate[3].ulValueLen = sizeof(true);
    sAESKeyTemplate[4].type = CKA_DECRYPT;
    sAESKeyTemplate[4].pValue = &true;
    sAESKeyTemplate[4].ulValueLen = sizeof(true);
    sAESKeyTemplate[5].type = CKA_SIGN;
    sAESKeyTemplate[5].pValue = &true;
    sAESKeyTemplate[5].ulValueLen = sizeof(true);
    sAESKeyTemplate[6].type = CKA_VERIFY;
    sAESKeyTemplate[6].pValue = &true;
    sAESKeyTemplate[6].ulValueLen = sizeof(true);
    sAESKeyTemplate[7].type = CKA_UNWRAP;
    sAESKeyTemplate[7].pValue = &true;
    sAESKeyTemplate[7].ulValueLen = sizeof(true);
    sAESKeyTemplate[8].type = CKA_VALUE_LEN;
    sAESKeyTemplate[8].pValue = &AESvalueLen;
    sAESKeyTemplate[8].ulValueLen = sizeof(AESvalueLen);


    /* DES3 key template */
    sDES3KeyTemplate[0].type = CKA_CLASS;
    sDES3KeyTemplate[0].pValue = &class;
    sDES3KeyTemplate[0].ulValueLen = sizeof(class);
    sDES3KeyTemplate[1].type = CKA_KEY_TYPE;
    sDES3KeyTemplate[1].pValue = &keyDES3Type;
    sDES3KeyTemplate[1].ulValueLen = sizeof(keyDES3Type);
    sDES3KeyTemplate[2].type = CKA_LABEL;
    sDES3KeyTemplate[2].pValue = DES3label;
    sDES3KeyTemplate[2].ulValueLen = sizeof(DES3label) - 1;
    sDES3KeyTemplate[3].type = CKA_ENCRYPT;
    sDES3KeyTemplate[3].pValue = &true;
    sDES3KeyTemplate[3].ulValueLen = sizeof(true);
    sDES3KeyTemplate[4].type = CKA_DECRYPT;
    sDES3KeyTemplate[4].pValue = &true;
    sDES3KeyTemplate[4].ulValueLen = sizeof(true);
    sDES3KeyTemplate[5].type = CKA_UNWRAP;
    sDES3KeyTemplate[5].pValue = &true;
    sDES3KeyTemplate[5].ulValueLen = sizeof(true);
    sDES3KeyTemplate[6].type = CKA_SIGN,
    sDES3KeyTemplate[6].pValue = &true;
    sDES3KeyTemplate[6].ulValueLen = sizeof(true);
    sDES3KeyTemplate[7].type = CKA_VERIFY;
    sDES3KeyTemplate[7].pValue = &true;
    sDES3KeyTemplate[7].ulValueLen = sizeof(true);
    sDES3KeyTemplate[8].type = CKA_VALUE_LEN;
    sDES3KeyTemplate[8].pValue = &DES3valueLen;
    sDES3KeyTemplate[8].ulValueLen = sizeof(DES3valueLen);

    secretValueTemplate[0].type = CKA_VALUE;
    secretValueTemplate[0].pValue = SECRET_VALUE;
    secretValueTemplate[0].ulValueLen = sizeof(SECRET_VALUE);

    /* mech init */
    memset(IV, 0x01, sizeof(IV));
    mech_DES3_CBC.mechanism = CKM_DES3_CBC;
    mech_DES3_CBC.pParameter = IV;
    mech_DES3_CBC.ulParameterLen = sizeof(IV);
    mech_DES3_CBC_PAD.mechanism = CKM_DES3_CBC_PAD;
    mech_DES3_CBC_PAD.pParameter = IV;
    mech_DES3_CBC_PAD.ulParameterLen = sizeof(IV);
    mech_AES_CBC.mechanism = CKM_AES_CBC;
    mech_AES_CBC.pParameter = IV;
    mech_AES_CBC.ulParameterLen = sizeof(IV);
    mech_AES_CBC_PAD.mechanism = CKM_AES_CBC_PAD;
    mech_AES_CBC_PAD.pParameter = IV;
    mech_AES_CBC_PAD.ulParameterLen = sizeof(IV);

    crv = pFunctionList->C_OpenSession(pSlotList[slotID],
                                       CKF_RW_SESSION | CKF_SERIAL_SESSION,
                                       NULL, NULL, &hRwSession);
    if (crv == CKR_OK) {
        PKM_LogIt("Opening a read/write session succeeded\n");
    } else {
        PKM_Error("Opening a read/write session failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    if (MODE == FIPSMODE) {
        crv = pFunctionList->C_GenerateKey(hRwSession, &sAESKeyMech,
                                           sAESKeyTemplate,
                                           NUM_ELEM(sAESKeyTemplate),
                                           &hAESSecKey);
        if (crv == CKR_OK) {
            PKM_Error("C_GenerateKey succeeded when not logged in.\n");
            return CKR_GENERAL_ERROR;
        } else {
            PKM_LogIt("C_GenerateKey returned as EXPECTED with 0x%08X, %-26s\n"
                      "since not logged in\n",
                      crv, PKM_CK_RVtoStr(crv));
        }
        crv = pFunctionList->C_GenerateKeyPair(hRwSession, &rsaKeyPairGenMech,
                                               rsaPubKeyTemplate,
                                               NUM_ELEM(rsaPubKeyTemplate),
                                               rsaPrivKeyTemplate,
                                               NUM_ELEM(rsaPrivKeyTemplate),
                                               &hRSApubKey, &hRSAprivKey);
        if (crv == CKR_OK) {
            PKM_Error("C_GenerateKeyPair succeeded when not logged in.\n");
            return CKR_GENERAL_ERROR;
        } else {
            PKM_LogIt("C_GenerateKeyPair returned as EXPECTED with 0x%08X, "
                      "%-26s\n since not logged in\n",
                      crv,
                      PKM_CK_RVtoStr(crv));
        }
    }

    crv = pFunctionList->C_Login(hRwSession, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Login with correct password succeeded\n");
    } else {
        PKM_Error("C_Login with correct password failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate an AES key ... \n");
    /* generate an AES Secret Key */
    crv = pFunctionList->C_GenerateKey(hRwSession, &sAESKeyMech,
                                       sAESKeyTemplate,
                                       NUM_ELEM(sAESKeyTemplate),
                                       &hAESSecKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateKey AES succeeded\n");
    } else {
        PKM_Error("C_GenerateKey AES failed with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate an 3DES key ...\n");
    /* generate an 3DES Secret Key */
    crv = pFunctionList->C_GenerateKey(hRwSession, &sDES3KeyGenMechanism,
                                       sDES3KeyTemplate,
                                       NUM_ELEM(sDES3KeyTemplate),
                                       &hDES3SecKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateKey DES3 succeeded\n");
    } else {
        PKM_Error("C_GenerateKey failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate DSA PQG domain parameters ... \n");
    /* Generate DSA domain parameters PQG */
    crv = pFunctionList->C_GenerateKey(hRwSession, &dsaParamGenMech,
                                       dsaParamGenTemplate,
                                       NUM_ELEM(dsaParamGenTemplate),
                                       &hDsaParams);
    if (crv == CKR_OK) {
        PKM_LogIt("DSA domain parameter generation succeeded\n");
    } else {
        PKM_Error("DSA domain parameter generation failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_GetAttributeValue(hRwSession, hDsaParams,
                                             dsaPubKeyTemplate, 3);
    if (crv == CKR_OK) {
        PKM_LogIt("Getting DSA domain parameters succeeded\n");
    } else {
        PKM_Error("Getting DSA domain parameters failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_DestroyObject(hRwSession, hDsaParams);
    if (crv == CKR_OK) {
        PKM_LogIt("Destroying DSA domain parameters succeeded\n");
    } else {
        PKM_Error("Destroying DSA domain parameters failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate a DSA key pair ... \n");
    /* Generate a persistent DSA key pair */
    crv = pFunctionList->C_GenerateKeyPair(hRwSession, &dsaKeyPairGenMech,
                                           dsaPubKeyTemplate,
                                           NUM_ELEM(dsaPubKeyTemplate),
                                           dsaPrivKeyTemplate,
                                           NUM_ELEM(dsaPrivKeyTemplate),
                                           &hDSApubKey, &hDSAprivKey);
    if (crv == CKR_OK) {
        PKM_LogIt("DSA key pair generation succeeded\n");
    } else {
        PKM_Error("DSA key pair generation failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate a RSA key pair ... \n");
    /*** GEN RSA Key ***/
    crv = pFunctionList->C_GenerateKeyPair(hRwSession, &rsaKeyPairGenMech,
                                           rsaPubKeyTemplate,
                                           NUM_ELEM(rsaPubKeyTemplate),
                                           rsaPrivKeyTemplate,
                                           NUM_ELEM(rsaPrivKeyTemplate),
                                           &hRSApubKey, &hRSAprivKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateKeyPair created an RSA key pair. \n");
    } else {
        PKM_Error("C_GenerateKeyPair failed to create an RSA key pair.\n"
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("**** Generation of keys completed ***** \n");

    /* verify that we can't read the Keys we generated */
    /* Try to read the RSA key */
    crv = pFunctionList->C_GetAttributeValue(hRwSession, hRSAprivKey, 
               rsaPrivValueTemplate, NUM_ELEM(rsaPrivValueTemplate));
    if (crv == CKR_ATTRIBUTE_SENSITIVE) {
	PKM_LogIt("C_GetAttributeValue correctly blocked attempt"
                  " to read RSA private key.\n");
    } else if (crv == CKR_OK) {
	PKM_Error("C_GetAttributeValue was able to read RSA private key,"
                  " should have been protected (FAIL).\n");
        return CKR_ATTRIBUTE_SENSITIVE;
    } else {
	PKM_Error("C_GetAttributeValue reading RSA private key returned"
                  " unexpected error:\n"
                  "0x%08x, %-26s\n", crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    /* RSA keys have multiple private elements, make sure all of them are
     * sensitive */
    for (i=0; i < NUM_ELEM(rsaPrivValueTemplate); i++) {
	if (rsaPrivValueTemplate[i].ulValueLen != -1) {
	    PKM_Error("C_GetAttributeValue was able to read %s "
                      "RSA private key attribute (FAIL).\n");
	    return CKR_ATTRIBUTE_SENSITIVE;
	}
    }

    /* Try to read the DSA key */
    secretValueTemplate[0].ulValueLen = sizeof(SECRET_VALUE);
    crv = pFunctionList->C_GetAttributeValue(hRwSession, hDSAprivKey, 
                                        secretValueTemplate, 1);
    if (crv == CKR_ATTRIBUTE_SENSITIVE) {
	PKM_LogIt("C_GetAttributeValue correctly blocked attempt"
                  " to read DSA private key.\n");
    } else if (crv == CKR_OK) {
	PKM_Error("C_GetAttributeValue was able to read DSA private key,"
                  " should have been protected (FAIL).\n");
        return CKR_ATTRIBUTE_SENSITIVE;
    } else {
	PKM_Error("C_GetAttributeValue reading DSA private key returned"
                  " unexpected error:\n"
                  "0x%08x, %-26s\n", crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* try to read the AES key */
    secretValueTemplate[0].ulValueLen = sizeof(SECRET_VALUE);
    crv = pFunctionList->C_GetAttributeValue(hRwSession, hAESSecKey, 
                                        secretValueTemplate, 1);
    if (crv == CKR_ATTRIBUTE_SENSITIVE) {
	PKM_LogIt("C_GetAttributeValue correctly blocked attempt"
                  " to read AES key.\n");
    } else if (crv == CKR_OK) {
	PKM_Error("C_GetAttributeValue was able to read AES key,"
                  " should have been protected (FAIL).\n");
        return CKR_ATTRIBUTE_SENSITIVE;
    } else {
	PKM_Error("C_GetAttributeValue reading AES key returned"
                  " unexpected error:\n"
                  "0x%08x, %-26s\n", crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* tryo to read the DES KEY */
    secretValueTemplate[0].ulValueLen = sizeof(SECRET_VALUE);
    crv = pFunctionList->C_GetAttributeValue(hRwSession, hDES3SecKey, 
                                        secretValueTemplate, 1);
    if (crv == CKR_ATTRIBUTE_SENSITIVE) {
	PKM_LogIt("C_GetAttributeValue correctly blocked attempt"
                  " to read DES 3 key.\n");
    } else if (crv == CKR_OK) {
	PKM_Error("C_GetAttributeValue was able to read DES 3 key,"
                  " should have been protected (FAIL).\n");
        return CKR_ATTRIBUTE_SENSITIVE;
    } else {
	PKM_Error("C_GetAttributeValue reading DES 3 key returned"
                  " unexpected error:\n"
                  "0x%08x, %-26s\n", crv, PKM_CK_RVtoStr(crv));
        return crv;
    }


    mech.mechanism = CKM_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    crv = PKM_WrapUnwrap(pFunctionList,
                         hRwSession,
                         hRSApubKey, hRSAprivKey,
                         &mech,
                         hAESSecKey,
                         sAESKeyTemplate,
                         NUM_ELEM(sAESKeyTemplate));

    if (crv == CKR_OK) {
        PKM_LogIt("PKM_WrapUnwrap using RSA keypair to wrap AES key "
                  "succeeded\n\n");
    } else {
        PKM_Error("PKM_WrapUnwrap using RSA keypair to wrap AES key failed "
                  "with 0x%08X, %-26s\n",
                  crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = PKM_WrapUnwrap(pFunctionList,
                         hRwSession,
                         hRSApubKey, hRSAprivKey,
                         &mech,
                         hDES3SecKey,
                         sDES3KeyTemplate,
                         NUM_ELEM(sDES3KeyTemplate));

    if (crv == CKR_OK) {
        PKM_LogIt("PKM_WrapUnwrap using RSA keypair to wrap DES3 key "
                  "succeeded\n\n");
    } else {
        PKM_Error("PKM_WrapUnwrap using RSA keypair to wrap DES3 key "
                  "failed with 0x%08X, %-26s\n",
                  crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = PKM_SecKeyCrypt(pFunctionList, hRwSession,
                          hAESSecKey, &mech_AES_CBC_PAD,
                          PLAINTEXT_PAD, sizeof(PLAINTEXT_PAD));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_SecKeyCrypt succeeded \n\n");
    } else {
        PKM_Error("PKM_SecKeyCrypt failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = PKM_SecKeyCrypt(pFunctionList, hRwSession,
                          hAESSecKey, &mech_AES_CBC,
                          PLAINTEXT, sizeof(PLAINTEXT));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_SecKeyCrypt AES succeeded \n\n");
    } else {
        PKM_Error("PKM_SecKeyCrypt failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = PKM_SecKeyCrypt(pFunctionList, hRwSession,
                          hDES3SecKey, &mech_DES3_CBC,
                          PLAINTEXT, sizeof(PLAINTEXT));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_SecKeyCrypt DES3 succeeded \n");
    } else {
        PKM_Error("PKM_SecKeyCrypt DES3 failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = PKM_SecKeyCrypt(pFunctionList, hRwSession,
                          hDES3SecKey, &mech_DES3_CBC_PAD,
                          PLAINTEXT_PAD, sizeof(PLAINTEXT_PAD));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_SecKeyCrypt DES3 succeeded \n\n");
    } else {
        PKM_Error("PKM_SecKeyCrypt DES3 failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    mech.mechanism = CKM_RSA_PKCS;
    crv = PKM_RecoverFunctions(pFunctionList, hRwSession,
                               hRSApubKey, hRSAprivKey,
                               &mech,
                               PLAINTEXT, sizeof(PLAINTEXT));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_RecoverFunctions for CKM_RSA_PKCS succeeded\n\n");
    } else {
        PKM_Error("PKM_RecoverFunctions failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    for (i = 0; i < sigRSAMechsSZ; i++) {

        mech.mechanism = sigRSAMechs[i].mechanism;

        crv = PKM_PubKeySign(pFunctionList, hRwSession,
                             hRSApubKey, hRSAprivKey,
                             &mech,
                             PLAINTEXT, sizeof(PLAINTEXT));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_PubKeySign succeeded for %-10s\n\n",
                      sigRSAMechs[i].mechanismStr);
        } else {
            PKM_Error("PKM_PubKeySign failed for %-10s  "
                      "with 0x%08X, %-26s\n",
                      sigRSAMechs[i].mechanismStr, crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }
        crv = PKM_DualFuncSign(pFunctionList, hRwSession,
                               hRSApubKey, hRSAprivKey,
                               &mech,
                               hAESSecKey, &mech_AES_CBC,
                               PLAINTEXT, sizeof(PLAINTEXT));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_DualFuncSign with AES secret key succeeded "
                      "for %-10s\n\n",
                      sigRSAMechs[i].mechanismStr);
        } else {
            PKM_Error("PKM_DualFuncSign with AES secret key failed "
                      "for %-10s  "
                      "with 0x%08X, %-26s\n",
                      sigRSAMechs[i].mechanismStr, crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }
        crv = PKM_DualFuncSign(pFunctionList, hRwSession,
                               hRSApubKey, hRSAprivKey,
                               &mech,
                               hDES3SecKey, &mech_DES3_CBC,
                               PLAINTEXT, sizeof(PLAINTEXT));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_DualFuncSign with DES3 secret key succeeded "
                      "for %-10s\n\n",
                      sigRSAMechs[i].mechanismStr);
        } else {
            PKM_Error("PKM_DualFuncSign with DES3 secret key failed "
                      "for %-10s  "
                      "with 0x%08X, %-26s\n",
                      sigRSAMechs[i].mechanismStr, crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }
        crv = PKM_DualFuncSign(pFunctionList, hRwSession,
                               hRSApubKey, hRSAprivKey,
                               &mech,
                               hAESSecKey, &mech_AES_CBC_PAD,
                               PLAINTEXT_PAD, sizeof(PLAINTEXT_PAD));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_DualFuncSign with AES secret key CBC_PAD "
                      "succeeded for %-10s\n\n",
                      sigRSAMechs[i].mechanismStr);
        } else {
            PKM_Error("PKM_DualFuncSign with AES secret key CBC_PAD "
                      "failed for %-10s  "
                      "with 0x%08X, %-26s\n",
                      sigRSAMechs[i].mechanismStr, crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }
        crv = PKM_DualFuncSign(pFunctionList, hRwSession,
                               hRSApubKey, hRSAprivKey,
                               &mech,
                               hDES3SecKey, &mech_DES3_CBC_PAD,
                               PLAINTEXT_PAD, sizeof(PLAINTEXT_PAD));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_DualFuncSign with DES3 secret key CBC_PAD "
                      "succeeded for %-10s\n\n",
                      sigRSAMechs[i].mechanismStr);
        } else {
            PKM_Error("PKM_DualFuncSign with DES3 secret key CBC_PAD "
                      "failed for %-10s  "
                      "with 0x%08X, %-26s\n",
                      sigRSAMechs[i].mechanismStr, crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }

    } /* end of RSA for loop */

    crv = PKM_PubKeySign(pFunctionList, hRwSession,
                         hDSApubKey, hDSAprivKey,
                         &dsaWithSha1Mech, PLAINTEXT, sizeof(PLAINTEXT));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_PubKeySign for DSAwithSHA1 succeeded \n\n");
    } else {
        PKM_Error("PKM_PubKeySign failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = PKM_DualFuncSign(pFunctionList, hRwSession,
                           hDSApubKey, hDSAprivKey,
                           &dsaWithSha1Mech,
                           hAESSecKey, &mech_AES_CBC,
                           PLAINTEXT, sizeof(PLAINTEXT));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_DualFuncSign with AES secret key succeeded "
                  "for DSAWithSHA1\n\n");
    } else {
        PKM_Error("PKM_DualFuncSign with AES secret key failed "
                  "for DSAWithSHA1 with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = PKM_DualFuncSign(pFunctionList, hRwSession,
                           hDSApubKey, hDSAprivKey,
                           &dsaWithSha1Mech,
                           hDES3SecKey, &mech_DES3_CBC,
                           PLAINTEXT, sizeof(PLAINTEXT));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_DualFuncSign with DES3 secret key succeeded "
                  "for DSAWithSHA1\n\n");
    } else {
        PKM_Error("PKM_DualFuncSign with DES3 secret key failed "
                  "for DSAWithSHA1 with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = PKM_DualFuncSign(pFunctionList, hRwSession,
                           hDSApubKey, hDSAprivKey,
                           &dsaWithSha1Mech,
                           hAESSecKey, &mech_AES_CBC_PAD,
                           PLAINTEXT_PAD, sizeof(PLAINTEXT_PAD));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_DualFuncSign with AES secret key CBC_PAD succeeded "
                  "for DSAWithSHA1\n\n");
    } else {
        PKM_Error("PKM_DualFuncSign with AES secret key CBC_PAD failed "
                  "for DSAWithSHA1 with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = PKM_DualFuncSign(pFunctionList, hRwSession,
                           hDSApubKey, hDSAprivKey,
                           &dsaWithSha1Mech,
                           hDES3SecKey, &mech_DES3_CBC_PAD,
                           PLAINTEXT_PAD, sizeof(PLAINTEXT_PAD));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_DualFuncSign with DES3 secret key CBC_PAD succeeded "
                  "for DSAWithSHA1\n\n");
    } else {
        PKM_Error("PKM_DualFuncSign with DES3 secret key CBC_PAD failed "
                  "for DSAWithSHA1 with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    for (i = 0; i < digestMechsSZ; i++) {
        mech.mechanism = digestMechs[i].mechanism;
        crv = PKM_Digest(pFunctionList, hRwSession,
                         &mech, hAESSecKey,
                         PLAINTEXT, sizeof(PLAINTEXT));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_Digest with AES secret key succeeded for %-10s\n\n",
                      digestMechs[i].mechanismStr);
        } else {
            PKM_Error("PKM_Digest with AES secret key failed for "
                      "%-10s with 0x%08X,  %-26s\n",
                      digestMechs[i].mechanismStr, crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }
        crv = PKM_DualFuncDigest(pFunctionList, hRwSession,
                                 hAESSecKey, &mech_AES_CBC,
                                 0, &mech,
                                 PLAINTEXT, sizeof(PLAINTEXT));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_DualFuncDigest with AES secret key succeeded\n\n");
        } else {
            PKM_Error("PKM_DualFuncDigest with AES secret key "
                      "failed with 0x%08X, %-26s\n",
                      crv,
                      PKM_CK_RVtoStr(crv));
        }

        crv = PKM_Digest(pFunctionList, hRwSession,
                         &mech, hDES3SecKey,
                         PLAINTEXT, sizeof(PLAINTEXT));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_Digest with DES3 secret key succeeded for %-10s\n\n",
                      digestMechs[i].mechanismStr);
        } else {
            PKM_Error("PKM_Digest with DES3 secret key failed for "
                      "%-10s with 0x%08X,  %-26s\n",
                      digestMechs[i].mechanismStr, crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }
        crv = PKM_DualFuncDigest(pFunctionList, hRwSession,
                                 hDES3SecKey, &mech_DES3_CBC,
                                 0, &mech,
                                 PLAINTEXT, sizeof(PLAINTEXT));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_DualFuncDigest DES3 secret key succeeded\n\n");
        } else {
            PKM_Error("PKM_DualFuncDigest DES3 secret key "
                      "failed with 0x%08X, %-26s\n",
                      crv,
                      PKM_CK_RVtoStr(crv));
        }

        crv = PKM_Digest(pFunctionList, hRwSession,
                         &mech, 0,
                         PLAINTEXT, sizeof(PLAINTEXT));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_Digest with no secret key succeeded for %-10s\n\n",
                      digestMechs[i].mechanismStr);
        } else {
            PKM_Error("PKM_Digest with no secret key failed for %-10s  "
                      "with 0x%08X, %-26s\n",
                      digestMechs[i].mechanismStr, crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }
    } /* end of digest loop */

    for (i = 0; i < hmacMechsSZ; i++) {
        mech.mechanism = hmacMechs[i].mechanism;
        crv = PKM_Hmac(pFunctionList, hRwSession,
                       hAESSecKey, &mech,
                       PLAINTEXT, sizeof(PLAINTEXT));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_Hmac with AES secret key succeeded for %-10s\n\n",
                      hmacMechs[i].mechanismStr);
        } else {
            PKM_Error("PKM_Hmac with AES secret key failed for %-10s "
                      "with 0x%08X, %-26s\n",
                      hmacMechs[i].mechanismStr, crv, PKM_CK_RVtoStr(crv));
            return crv;
        }
        if ((MODE == FIPSMODE) && (mech.mechanism == CKM_SHA512_HMAC))
            break;
        crv = PKM_Hmac(pFunctionList, hRwSession,
                       hDES3SecKey, &mech,
                       PLAINTEXT, sizeof(PLAINTEXT));
        if (crv == CKR_OK) {
            PKM_LogIt("PKM_Hmac with DES3 secret key succeeded for %-10s\n\n",
                      hmacMechs[i].mechanismStr);
        } else {
            PKM_Error("PKM_Hmac with DES3 secret key failed for %-10s "
                      "with 0x%08X,  %-26s\n",
                      hmacMechs[i].mechanismStr, crv, PKM_CK_RVtoStr(crv));
            return crv;
        }

    } /* end of hmac loop */

    crv = pFunctionList->C_Logout(hRwSession);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Logout succeeded\n");
    } else {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_CloseSession(hRwSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    return crv;
}

/*
 * Try to extract a key from the token
 */
#define KEY_STRING "My Magic Known Key"
CK_RV
PKM_CSPTests(CK_FUNCTION_LIST_PTR pFunctionList,
             CK_SLOT_ID *pSlotList, CK_ULONG slotID,
             CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen,
	     unsigned char *heap_top)
{
    unsigned char our_stack;
    CK_SESSION_HANDLE hSession;
    CK_RV crv = CKR_OK;
    CK_RV crv1 = CKR_OK;

    CK_BYTE secret_key[sizeof(KEY_STRING)];  

    /*** AES Key ***/
    CK_MECHANISM sAESKeyMech = {
        CKM_AES_KEY_GEN, NULL, 0
    };
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE keyAESType = CKK_AES;
    CK_KEY_TYPE keySecretType = CKK_GENERIC_SECRET;
    CK_UTF8CHAR AESlabel[] = "An AES secret key object";
    CK_UTF8CHAR Secretlabel[] = "An HMAC secret key object";
    CK_ULONG AESvalueLen = 32;
    CK_ATTRIBUTE sAESKeyTemplate[9];
    CK_ATTRIBUTE sHMacKeyTemplate[8];
    CK_OBJECT_HANDLE hAESSecKey;
    CK_OBJECT_HANDLE hMacKey;

    CK_MECHANISM mech_AES_CBC_PAD;
    CK_MECHANISM mech_SHA_256_HMAC = { CKM_SHA256_HMAC, NULL, 0 };
    CK_BYTE IV[16];
    CK_ULONG encryptedLen;
    CK_BYTE encrypted_key[128];

    unsigned int i;
    unsigned char *heap1;
    unsigned char *heap2;
    unsigned char *stack_bottom;
    unsigned char their_stack;

    stack_bottom = &their_stack;

    PKM_LogIt("PKM_CSPTests started\n");
    NUMTESTS++; /* increment NUMTESTS */

    /* AES key template */
    sAESKeyTemplate[0].type = CKA_CLASS;
    sAESKeyTemplate[0].pValue = &class;
    sAESKeyTemplate[0].ulValueLen = sizeof(class);
    sAESKeyTemplate[1].type = CKA_KEY_TYPE;
    sAESKeyTemplate[1].pValue = &keyAESType;
    sAESKeyTemplate[1].ulValueLen = sizeof(keyAESType);
    sAESKeyTemplate[2].type = CKA_LABEL;
    sAESKeyTemplate[2].pValue = AESlabel;
    sAESKeyTemplate[2].ulValueLen = sizeof(AESlabel) - 1;
    sAESKeyTemplate[3].type = CKA_ENCRYPT;
    sAESKeyTemplate[3].pValue = &true;
    sAESKeyTemplate[3].ulValueLen = sizeof(true);
    sAESKeyTemplate[4].type = CKA_DECRYPT;
    sAESKeyTemplate[4].pValue = &true;
    sAESKeyTemplate[4].ulValueLen = sizeof(true);
    sAESKeyTemplate[5].type = CKA_SIGN;
    sAESKeyTemplate[5].pValue = &true;
    sAESKeyTemplate[5].ulValueLen = sizeof(true);
    sAESKeyTemplate[6].type = CKA_VERIFY;
    sAESKeyTemplate[6].pValue = &true;
    sAESKeyTemplate[6].ulValueLen = sizeof(true);
    sAESKeyTemplate[7].type = CKA_UNWRAP;
    sAESKeyTemplate[7].pValue = &true;
    sAESKeyTemplate[7].ulValueLen = sizeof(true);
    sAESKeyTemplate[8].type = CKA_VALUE_LEN;
    sAESKeyTemplate[8].pValue = &AESvalueLen;
    sAESKeyTemplate[8].ulValueLen = sizeof(AESvalueLen);

    /* HMac key template */
    sHMacKeyTemplate[0].type = CKA_CLASS;
    sHMacKeyTemplate[0].pValue = &class;
    sHMacKeyTemplate[0].ulValueLen = sizeof(class);
    sHMacKeyTemplate[1].type = CKA_KEY_TYPE;
    sHMacKeyTemplate[1].pValue = &keySecretType;
    sHMacKeyTemplate[1].ulValueLen = sizeof(keySecretType);
    sHMacKeyTemplate[2].type = CKA_LABEL;
    sHMacKeyTemplate[2].pValue = Secretlabel;
    sHMacKeyTemplate[2].ulValueLen = sizeof(Secretlabel) - 1;
    sHMacKeyTemplate[3].type = CKA_ENCRYPT;
    sHMacKeyTemplate[3].pValue = &true;
    sHMacKeyTemplate[3].ulValueLen = sizeof(true);
    sHMacKeyTemplate[4].type = CKA_DECRYPT;
    sHMacKeyTemplate[4].pValue = &true;
    sHMacKeyTemplate[4].ulValueLen = sizeof(true);
    sHMacKeyTemplate[5].type = CKA_SIGN;
    sHMacKeyTemplate[5].pValue = &true;
    sHMacKeyTemplate[5].ulValueLen = sizeof(true);
    sHMacKeyTemplate[6].type = CKA_VERIFY;
    sHMacKeyTemplate[6].pValue = &true;
    sHMacKeyTemplate[6].ulValueLen = sizeof(true);
    sHMacKeyTemplate[7].type = CKA_UNWRAP;
    sHMacKeyTemplate[7].pValue = &true;
    sHMacKeyTemplate[7].ulValueLen = sizeof(true);

    /* mech init */
    memset(IV, 0x01, sizeof(IV));
    mech_AES_CBC_PAD.mechanism = CKM_AES_CBC_PAD;
    mech_AES_CBC_PAD.pParameter = IV;
    mech_AES_CBC_PAD.ulParameterLen = sizeof(IV);

    crv = pFunctionList->C_OpenSession(pSlotList[slotID],
                                       CKF_SERIAL_SESSION,
                                       NULL, NULL, &hSession);
    if (crv == CKR_OK) {
        PKM_LogIt("Opening a session succeeded\n");
    } else {
        PKM_Error("Opening a session failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_Login(hSession, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Login with correct password succeeded\n");
    } else {
        PKM_Error("C_Login with correct password failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate an AES key ... \n");
    /* generate an AES Secret Key */
    crv = pFunctionList->C_GenerateKey(hSession, &sAESKeyMech,
                                       sAESKeyTemplate,
                                       NUM_ELEM(sAESKeyTemplate),
                                       &hAESSecKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateKey AES succeeded\n");
    } else {
        PKM_Error("C_GenerateKey AES failed with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

/* use macros to minimize stack clobbering */
#define SCAN_STACK(rc,message, key, len, stack_bottom, i) \
    rc = CKR_OK;\
    for(i=0; i < 4096*3; i++) { \
	if ((*(stack_bottom-i) == key[0]) && (memcmp(stack_bottom-i,key,len) == 0)) { \
	    PKM_LogIt(message ": key found on stack @ 0x%lx\n", stack_bottom-i); \
	    rc = CKR_ATTRIBUTE_SENSITIVE;\
	    break;\
	} }
#define SCAN_HEAP(rc, message, key, len, heap_top, h1, h2) \
    rc = CKR_OK; \
    h2 = sbrk(0); \
    for (h1= heap_top; h1 < h2; h1++) { \
	if ((*h1 == key[0]) && (memcmp(h1,key,len) == 0)) { \
	    PKM_LogIt(message ": key found on heap @%lx\n", h1); \
	    rc = CKR_ATTRIBUTE_SENSITIVE;\
	    break;\
	} }

    /* Make sure we aren't leaking plain text on the stack or heap */
    /* We stan the stack after every call to make sure the data wasn't leaked */
    /* We scan the heap one the CSP's have been deleted. Since this is a software module, we expect to finde
     * the CSP on the heap while it is active. */

    /* verify our stack scanner */
    memcpy(secret_key, KEY_STRING, sizeof(KEY_STRING));
    stack_bottom = &our_stack;
    SCAN_STACK(crv,"Verify stack scanner", secret_key, sizeof(KEY_STRING), stack_bottom, i)
    stack_bottom = &their_stack;
    if (crv != CKR_ATTRIBUTE_SENSITIVE) {
	PKM_Error("SCAN_STACK internal test failed, should have found key on test stack\n");
	return crv;
    } else {
	PKM_LogIt("Verify SCAN_STACK succeeded\n");
    }

    /* Encrypt data */
    crv = pFunctionList->C_EncryptInit(hSession, &mech_AES_CBC_PAD, hAESSecKey);
    encryptedLen=sizeof(encrypted_key);
    if (crv == CKR_OK) {
        PKM_LogIt("C_EncryptInit succeeded\n");
    } else {
        PKM_Error("C_EncryptInit failed with 0x%08X,  %-26s\n",
                      crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Encrypt(hSession, secret_key, sizeof(KEY_STRING),
                                         encrypted_key, &encryptedLen);
    SCAN_STACK(crv1, "Encypting the Key", secret_key, sizeof(KEY_STRING), stack_bottom, i)
    if (crv1 != CKR_OK) {
	PKM_Error("SCAN_STACK leaked the key as plain text in C_Encrypt\n");
	return crv1;
    } else {
	PKM_LogIt("SCAN_STACK after C_Encrypt succeeded\n");
    }
    SCAN_HEAP(crv1, "Encrypting the Key", secret_key, sizeof(KEY_STRING), heap_top, heap1, heap2)
    if (crv1 != CKR_OK) {
	PKM_Error("SCAN_HEAP leaked the key as plain text in C_Encrypt\n");
	return crv1;
    } else {
	PKM_LogIt("SCAN_HEAP after C_Encrypt succeeded\n");
    }
    if (crv == CKR_OK) {
        PKM_LogIt("C_Encrypt succeeded\n");
    } else {
        PKM_Error("C_Encrypt failed with 0x%08X,  %-26s\n",
                      crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_UnwrapKey(
        hSession, &mech_AES_CBC_PAD, hAESSecKey,
        encrypted_key, encryptedLen, sHMacKeyTemplate,
        NUM_ELEM(sHMacKeyTemplate),
       &hMacKey);
    SCAN_STACK(crv1, "Unwrapping the Key", secret_key, sizeof(KEY_STRING), stack_bottom, i)
    if (crv1 != CKR_OK) {
	PKM_Error("SCAN_STACK leaked the key after unwrapping it in C_UnwrapKey\n");
	return crv1;
    } else {
	PKM_LogIt("SCAN_STACK after C_UnwrapKey succeeded\n");
    }
    /* The key is active, so it should be available on the heap */
    SCAN_HEAP(crv1, "Verifying the heap scanner", secret_key, sizeof(KEY_STRING), heap_top, heap1, heap2);
    if (crv1 != CKR_ATTRIBUTE_SENSITIVE) {
	PKM_Error("SCAN_HEAP internal test failed, should have found key on test stack\n");
	return crv1;
    } else {
	PKM_LogIt("Verify SCAN_HEAP succeeded\n");
    }
    if (crv == CKR_OK) {
        PKM_LogIt("C_UnwrapKey succeeded\n");
    } else {
        PKM_Error("C_UnwrapKey failed with 0x%08X,  %-26s\n",
                      crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = PKM_Hmac(pFunctionList, hSession,
                       hMacKey, &mech_SHA_256_HMAC,
                       PLAINTEXT, sizeof(PLAINTEXT));
    SCAN_STACK(crv1, "Unwrapping the Key", secret_key, sizeof(KEY_STRING), stack_bottom, i)
    if (crv1 != CKR_OK) {
	PKM_Error("SCAN_STACK leaked the key after using it in HMAC operation\n");
	return crv1;
    } else {
	PKM_LogIt("SCAN_STACK after HMAC succeeded\n");
    }
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_Hmac succeeded\n");
    } else {
        PKM_Error("PKM_Hmac failed with 0x%08X,  %-26s\n",
                      crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_Logout(hSession);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Logout succeeded\n");
    } else {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_CloseSession(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    SCAN_STACK(crv, "Close Session", secret_key, sizeof(KEY_STRING), stack_bottom, i)
    if (crv != CKR_OK) {
	PKM_Error("SCAN_STACK leaked the key after Closing the session\n");
	return crv;
    } else {
	PKM_LogIt("SCAN_STACK session close succeeded\n");
    }
    SCAN_HEAP(crv, "Freeing the key", secret_key, sizeof(KEY_STRING), heap_top, heap1, heap2)
    if (crv != CKR_OK) {
	PKM_Error("SCAN_HEAP leaked the key as plain text after it was deleted\n");
	return crv;
    } else {
	PKM_LogIt("SCAN_HEAP after key release succeeded\n");
    }

    return crv;
}

void
PKM_LogIt(const char *fmt, ...)
{
    va_list args;

    if (verbose) {
        va_start(args, fmt);
        if (MODE == FIPSMODE) {
            printf("FIPS MODE: ");
        } else if (MODE == NONFIPSMODE) {
            printf("NON FIPS MODE: ");
        } else if (MODE == HYBRIDMODE) {
            printf("Hybrid MODE: ");
        }
        vprintf(fmt, args);
        va_end(args);
    }
}

void
PKM_Error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    if (MODE == FIPSMODE) {
        fprintf(stderr, "\nFIPS MODE PKM_Error: ");
    } else if (MODE == NONFIPSMODE) {
        fprintf(stderr, "NON FIPS MODE PKM_Error: ");
    } else if (MODE == HYBRIDMODE) {
        fprintf(stderr, "Hybrid MODE PKM_Error: ");
    } else
        fprintf(stderr, "NOMODE PKM_Error: ");
    vfprintf(stderr, fmt, args);
    va_end(args);
}
CK_SLOT_ID *
PKM_GetSlotList(CK_FUNCTION_LIST_PTR pFunctionList,
                CK_ULONG slotID)
{
    CK_RV crv = CKR_OK;
    CK_SLOT_ID *pSlotList = NULL;
    CK_ULONG slotCount;

    PKM_LogIt("PKM_GetSlotList started\n");
    NUMTESTS++; /* increment NUMTESTS */

    /* Get slot list */
    crv = pFunctionList->C_GetSlotList(CK_FALSE /* all slots */,
                                       NULL, &slotCount);
    if (crv != CKR_OK) {
        PKM_Error("C_GetSlotList failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return NULL;
    }
    PKM_LogIt("C_GetSlotList reported there are %lu slots\n", slotCount);
    pSlotList = (CK_SLOT_ID *)malloc(slotCount * sizeof(CK_SLOT_ID));
    if (!pSlotList) {
        PKM_Error("failed to allocate slot list\n");
        return NULL;
    }
    crv = pFunctionList->C_GetSlotList(CK_FALSE /* all slots */,
                                       pSlotList, &slotCount);
    if (crv != CKR_OK) {
        PKM_Error("C_GetSlotList failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        if (pSlotList)
            free(pSlotList);
        return NULL;
    }
    return pSlotList;
}

CK_RV
PKM_InitPWforDB(CK_FUNCTION_LIST_PTR pFunctionList,
                CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen)
{
    CK_RV crv = CKR_OK;
    CK_SESSION_HANDLE hSession;
    static const CK_UTF8CHAR testPin[] = { "0Mozilla" };
    static const CK_UTF8CHAR weakPin[] = { "mozilla" };

    PKM_LogIt("PKM_InitPWforDB started\n");
    crv = pFunctionList->C_OpenSession(pSlotList[slotID],
                                       CKF_RW_SESSION | CKF_SERIAL_SESSION,
                                       NULL, NULL, &hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_OpenSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Login(hSession, CKU_USER, (CK_UTF8CHAR *)testPin,
						 strlen((char *)testPin));
    if (crv == CKR_OK) {
	PKM_Error(
"C_Login as USER incorrectly succeeded on uninitialized token.\n");
	return CKR_DEVICE_ERROR;
    } else {
        PKM_LogIt(
"C_Login as user correctly failed on uninitialized token with "
                      "0x%08X, %-26s\n",
                      crv, PKM_CK_RVtoStr(crv));
    }

    crv = pFunctionList->C_Login(hSession, CKU_SO, NULL, 0);
    if (crv != CKR_OK) {
        PKM_Error("C_Login as SSO failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    } else {
        PKM_LogIt("C_Login as SSO succeeded on uninitialized token\n");
    }
    if (MODE == FIPSMODE) {
        crv = pFunctionList->C_InitPIN(hSession, (CK_UTF8CHAR *)weakPin,
                                       strlen((char *)weakPin));
        if (crv == CKR_OK) {
            PKM_Error("C_InitPIN with a weak password succeeded\n");
            return CKR_DEVICE_ERROR;
        } else {
            PKM_LogIt("C_InitPIN with a weak password failed with "
                      "0x%08X, %-26s\n",
                      crv, PKM_CK_RVtoStr(crv));
        }
    }
    crv = pFunctionList->C_InitPIN(hSession, (CK_UTF8CHAR *)testPin,
                                   strlen((char *)testPin));
    if (crv == CKR_OK) {
        PKM_LogIt("C_InitPIN succeeded\n");
    } else {
        PKM_Error("C_InitPIN failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Logout(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_CloseSession(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_OpenSession(pSlotList[slotID],
                                       CKF_RW_SESSION | CKF_SERIAL_SESSION,
                                       NULL, NULL, &hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_OpenSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_Login(hSession, CKU_USER, (CK_UTF8CHAR *)testPin,
                                 strlen((const char *)testPin));
    if (crv != CKR_OK) {
        PKM_Error("C_Login USER failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    if (MODE == FIPSMODE) {
        crv = pFunctionList->C_SetPIN(
            hSession, (CK_UTF8CHAR *)testPin,
            strlen((const char *)testPin),
            (CK_UTF8CHAR *)weakPin,
            strlen((const char *)weakPin));
        if (crv == CKR_OK) {
            PKM_Error("C_SetPIN with a weak password succeeded\n");
            return crv;
        } else {
            PKM_LogIt("C_SetPIN with a weak password returned with "
                      "0x%08X, %-26s\n",
                      crv, PKM_CK_RVtoStr(crv));
        }
    }
    crv = pFunctionList->C_SetPIN(
        hSession, (CK_UTF8CHAR *)testPin,
        strlen((const char *)testPin),
        pwd, pwdLen);
    if (crv != CKR_OK) {
        PKM_Error("C_SetPin failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    } else {
	PKM_LogIt("C_SetPin succeeded\n");
    }
    /* try setting the pin with the old pin */
    crv = pFunctionList->C_SetPIN(
        hSession, (CK_UTF8CHAR *)testPin,
        strlen((const char *)testPin),
        pwd, pwdLen);
    if (crv != CKR_OK) {
        PKM_LogIt("C_SetPin with old pin failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
    } else {
        PKM_Error("C_SetPin with old pin incorrectly succeeded\n");
    }
    crv = pFunctionList->C_Logout(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_CloseSession(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    return crv;
}

CK_RV
PKM_ShowInfo(CK_FUNCTION_LIST_PTR pFunctionList, CK_ULONG slotID)
{
    CK_RV crv = CKR_OK;
    CK_INFO info;
    CK_SLOT_ID *pSlotList = NULL;
    unsigned i;

    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;
    CK_FLAGS bitflag;

    PKM_LogIt("PKM_ShowInfo started\n");
    NUMTESTS++; /* increment NUMTESTS */

    crv = pFunctionList->C_GetInfo(&info);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GetInfo succeeded\n");
    } else {
        PKM_Error("C_GetInfo failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    PKM_LogIt("General information about the PKCS #11 library:\n");
    PKM_LogIt("    PKCS #11 version: %d.%d\n",
              (int)info.cryptokiVersion.major,
              (int)info.cryptokiVersion.minor);
    PKM_LogIt("    manufacturer ID: %.32s\n", info.manufacturerID);
    PKM_LogIt("    flags: 0x%08lX\n", info.flags);
    PKM_LogIt("    library description: %.32s\n", info.libraryDescription);
    PKM_LogIt("    library version: %d.%d\n",
              (int)info.libraryVersion.major, (int)info.libraryVersion.minor);
    PKM_LogIt("\n");

    /* Get slot list */
    pSlotList = PKM_GetSlotList(pFunctionList, slotID);
    if (pSlotList == NULL) {
        PKM_Error("PKM_GetSlotList failed with \n");
        return crv;
    }
    crv = pFunctionList->C_GetSlotInfo(pSlotList[slotID], &slotInfo);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GetSlotInfo succeeded\n");
    } else {
        PKM_Error("C_GetSlotInfo failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    PKM_LogIt("Information about slot %lu:\n", pSlotList[slotID]);
    PKM_LogIt("    slot description: %.64s\n", slotInfo.slotDescription);
    PKM_LogIt("    slot manufacturer ID: %.32s\n", slotInfo.manufacturerID);
    PKM_LogIt("    flags: 0x%08lX\n", slotInfo.flags);
    bitflag = 1;
    for (i = 0; i < sizeof(slotFlagName) / sizeof(slotFlagName[0]); i++) {
        if (slotInfo.flags & bitflag) {
            PKM_LogIt("           %s\n", slotFlagName[i]);
        }
        bitflag <<= 1;
    }
    PKM_LogIt("    slot's hardware version number: %d.%d\n",
              (int)slotInfo.hardwareVersion.major,
              (int)slotInfo.hardwareVersion.minor);
    PKM_LogIt("    slot's firmware version number: %d.%d\n",
              (int)slotInfo.firmwareVersion.major,
              (int)slotInfo.firmwareVersion.minor);
    PKM_LogIt("\n");

    crv = pFunctionList->C_GetTokenInfo(pSlotList[slotID], &tokenInfo);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GetTokenInfo succeeded\n");
    } else {
        PKM_Error("C_GetTokenInfo failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    PKM_LogIt("Information about the token in slot %lu:\n",
              pSlotList[slotID]);
    PKM_LogIt("    label: %.32s\n", tokenInfo.label);
    PKM_LogIt("    device manufacturer ID: %.32s\n",
              tokenInfo.manufacturerID);
    PKM_LogIt("    device model: %.16s\n", tokenInfo.model);
    PKM_LogIt("    device serial number: %.16s\n", tokenInfo.serialNumber);
    PKM_LogIt("    flags: 0x%08lX\n", tokenInfo.flags);
    bitflag = 1;
    for (i = 0; i < sizeof(tokenFlagName) / sizeof(tokenFlagName[0]); i++) {
        if (tokenInfo.flags & bitflag) {
            PKM_LogIt("           %s\n", tokenFlagName[i]);
        }
        bitflag <<= 1;
    }
    PKM_LogIt("    maximum session count: %lu\n",
              tokenInfo.ulMaxSessionCount);
    PKM_LogIt("    session count: %lu\n", tokenInfo.ulSessionCount);
    PKM_LogIt("    maximum read/write session count: %lu\n",
              tokenInfo.ulMaxRwSessionCount);
    PKM_LogIt("    read/write session count: %lu\n",
              tokenInfo.ulRwSessionCount);
    PKM_LogIt("    maximum PIN length: %lu\n", tokenInfo.ulMaxPinLen);
    PKM_LogIt("    minimum PIN length: %lu\n", tokenInfo.ulMinPinLen);
    PKM_LogIt("    total public memory: %lu\n",
              tokenInfo.ulTotalPublicMemory);
    PKM_LogIt("    free public memory: %lu\n",
              tokenInfo.ulFreePublicMemory);
    PKM_LogIt("    total private memory: %lu\n",
              tokenInfo.ulTotalPrivateMemory);
    PKM_LogIt("    free private memory: %lu\n",
              tokenInfo.ulFreePrivateMemory);
    PKM_LogIt("    hardware version number: %d.%d\n",
              (int)tokenInfo.hardwareVersion.major,
              (int)tokenInfo.hardwareVersion.minor);
    PKM_LogIt("    firmware version number: %d.%d\n",
              (int)tokenInfo.firmwareVersion.major,
              (int)tokenInfo.firmwareVersion.minor);
    if (tokenInfo.flags & CKF_CLOCK_ON_TOKEN) {
        PKM_LogIt("    current time: %.16s\n", tokenInfo.utcTime);
    }
    PKM_LogIt("PKM_ShowInfo done \n\n");
    free(pSlotList);
    return crv;
}

CK_RV 
PKM_ErrorState(CK_FUNCTION_LIST_PTR pFunctionList, 
             CK_SLOT_ID *pSlotList, CK_ULONG slotID,
	     CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen,
             CK_C_INITIALIZE_ARGS_NSS *initArgs)
{
    CK_SESSION_HANDLE hRwSession;

    CK_RV crv = CKR_OK;

    /* We get a bunch of keys so we can try actually do stuff with the functions which we expect to fail. */
    /**** RSA Key ***/
    CK_KEY_TYPE rsatype = CKK_RSA;
    CK_MECHANISM rsaKeyPairGenMech;
    CK_MECHANISM rsaMech;
    CK_BYTE subject[] = { "RSA Private Key" };
    CK_ULONG modulusBits = RSA_BITS;
    CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
    CK_BYTE id[] = { "RSA123" };
    CK_ATTRIBUTE rsaPubKeyTemplate[9];
    CK_ATTRIBUTE rsaPrivKeyTemplate[11];
    CK_OBJECT_HANDLE hRSApubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hRSAprivKey = CK_INVALID_HANDLE;

    /*** AES Key ***/
    CK_MECHANISM sAESKeyMech = {
        CKM_AES_KEY_GEN, NULL, 0
    };
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE keyAESType = CKK_AES;
    CK_UTF8CHAR AESlabel[] = "An AES secret key object";
    CK_ULONG AESvalueLen = 32;
    CK_ATTRIBUTE sAESKeyTemplate[9];
    CK_OBJECT_HANDLE hAESSecKey;
    CK_MECHANISM mech_AES_CBC;
    CK_BYTE IV[16];

    /* Other mechanisms */
    CK_MECHANISM tls_mech;
    CK_SSL3_MASTER_KEY_DERIVE_PARAMS tls_params;
    CK_MECHANISM mech_SHA_256_hmac = { CKM_SHA256_HMAC, NULL, 0 };
    CK_MECHANISM mech_SHA_256 = { CKM_SHA256, NULL, 0 };

    /* additional data */
    CK_BYTE bigRandomData[128*1024]; /* more than 64K */
    CK_MECHANISM_INFO minfo;
    CK_SESSION_INFO sess_info;
    CK_ULONG dummyULong = 0;
    CK_ULONG dummyULong2 = 0;

    unsigned int i;

    PKM_LogIt("PKM_ErrorState started\n");
    NUMTESTS++; /* increment NUMTESTS */

    /* RSA key init */
    rsaKeyPairGenMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    rsaKeyPairGenMech.pParameter = NULL_PTR;
    rsaKeyPairGenMech.ulParameterLen = 0;
    rsaMech.mechanism = CKM_RSA_PKCS;
    rsaMech.pParameter = NULL_PTR;
    rsaMech.ulParameterLen = 0;

    rsaPubKeyTemplate[0].type = CKA_KEY_TYPE;
    rsaPubKeyTemplate[0].pValue = &rsatype;
    rsaPubKeyTemplate[0].ulValueLen = sizeof(rsatype);
    rsaPubKeyTemplate[1].type = CKA_PRIVATE;
    rsaPubKeyTemplate[1].pValue = &true;
    rsaPubKeyTemplate[1].ulValueLen = sizeof(true);
    rsaPubKeyTemplate[2].type = CKA_ENCRYPT;
    rsaPubKeyTemplate[2].pValue = &true;
    rsaPubKeyTemplate[2].ulValueLen = sizeof(true);
    rsaPubKeyTemplate[3].type = CKA_DECRYPT;
    rsaPubKeyTemplate[3].pValue = &true;
    rsaPubKeyTemplate[3].ulValueLen = sizeof(true);
    rsaPubKeyTemplate[4].type = CKA_VERIFY;
    rsaPubKeyTemplate[4].pValue = &true;
    rsaPubKeyTemplate[4].ulValueLen = sizeof(true);
    rsaPubKeyTemplate[5].type = CKA_SIGN;
    rsaPubKeyTemplate[5].pValue = &true;
    rsaPubKeyTemplate[5].ulValueLen = sizeof(true);
    rsaPubKeyTemplate[6].type = CKA_WRAP;
    rsaPubKeyTemplate[6].pValue = &true;
    rsaPubKeyTemplate[6].ulValueLen = sizeof(true);
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
    rsaPrivKeyTemplate[1].pValue = &true;
    rsaPrivKeyTemplate[1].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[2].type = CKA_PRIVATE;
    rsaPrivKeyTemplate[2].pValue = &true;
    rsaPrivKeyTemplate[2].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[3].type = CKA_SUBJECT;
    rsaPrivKeyTemplate[3].pValue = subject;
    rsaPrivKeyTemplate[3].ulValueLen = sizeof(subject);
    rsaPrivKeyTemplate[4].type = CKA_ID;
    rsaPrivKeyTemplate[4].pValue = id;
    rsaPrivKeyTemplate[4].ulValueLen = sizeof(id);
    rsaPrivKeyTemplate[5].type = CKA_SENSITIVE;
    rsaPrivKeyTemplate[5].pValue = &true;
    rsaPrivKeyTemplate[5].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[6].type = CKA_ENCRYPT;
    rsaPrivKeyTemplate[6].pValue = &true;
    rsaPrivKeyTemplate[6].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[7].type = CKA_DECRYPT;
    rsaPrivKeyTemplate[7].pValue = &true;
    rsaPrivKeyTemplate[7].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[8].type = CKA_VERIFY;
    rsaPrivKeyTemplate[8].pValue = &true;
    rsaPrivKeyTemplate[8].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[9].type = CKA_SIGN;
    rsaPrivKeyTemplate[9].pValue = &true;
    rsaPrivKeyTemplate[9].ulValueLen = sizeof(true);
    rsaPrivKeyTemplate[10].type = CKA_UNWRAP;
    rsaPrivKeyTemplate[10].pValue = &true;
    rsaPrivKeyTemplate[10].ulValueLen = sizeof(true);

    /* AES key template */
    sAESKeyTemplate[0].type = CKA_CLASS;
    sAESKeyTemplate[0].pValue = &class;
    sAESKeyTemplate[0].ulValueLen = sizeof(class);
    sAESKeyTemplate[1].type = CKA_KEY_TYPE;
    sAESKeyTemplate[1].pValue = &keyAESType;
    sAESKeyTemplate[1].ulValueLen = sizeof(keyAESType);
    sAESKeyTemplate[2].type = CKA_LABEL;
    sAESKeyTemplate[2].pValue = AESlabel;
    sAESKeyTemplate[2].ulValueLen = sizeof(AESlabel) - 1;
    sAESKeyTemplate[3].type = CKA_ENCRYPT;
    sAESKeyTemplate[3].pValue = &true;
    sAESKeyTemplate[3].ulValueLen = sizeof(true);
    sAESKeyTemplate[4].type = CKA_DECRYPT;
    sAESKeyTemplate[4].pValue = &true;
    sAESKeyTemplate[4].ulValueLen = sizeof(true);
    sAESKeyTemplate[5].type = CKA_SIGN;
    sAESKeyTemplate[5].pValue = &true;
    sAESKeyTemplate[5].ulValueLen = sizeof(true);
    sAESKeyTemplate[6].type = CKA_VERIFY;
    sAESKeyTemplate[6].pValue = &true;
    sAESKeyTemplate[6].ulValueLen = sizeof(true);
    sAESKeyTemplate[7].type = CKA_UNWRAP;
    sAESKeyTemplate[7].pValue = &true;
    sAESKeyTemplate[7].ulValueLen = sizeof(true);
    sAESKeyTemplate[8].type = CKA_VALUE_LEN;
    sAESKeyTemplate[8].pValue = &AESvalueLen;
    sAESKeyTemplate[8].ulValueLen = sizeof(AESvalueLen);

    /* mech init */
    memset(IV, 0x01, sizeof(IV));
    mech_AES_CBC.mechanism = CKM_AES_CBC;
    mech_AES_CBC.pParameter = IV;
    mech_AES_CBC.ulParameterLen = sizeof(IV);
    tls_mech.mechanism = CKM_TLS_MASTER_KEY_DERIVE;
    tls_mech.pParameter = &tls_params;
    tls_mech.ulParameterLen = sizeof(tls_params);
    tls_params.RandomInfo.pClientRandom = (unsigned char *)bigRandomData;
    tls_params.RandomInfo.ulClientRandomLen = TLS_RANDOM_LEN;
    tls_params.RandomInfo.pServerRandom = (unsigned char *)&bigRandomData[TLS_RANDOM_LEN];
    tls_params.RandomInfo.ulServerRandomLen = TLS_RANDOM_LEN;

    crv = pFunctionList->C_OpenSession(pSlotList[slotID],
                                       CKF_RW_SESSION | CKF_SERIAL_SESSION,
                                       NULL, NULL, &hRwSession);
    if (crv == CKR_OK) {
        PKM_LogIt("Opening a read/write session succeeded\n");
    } else {
        PKM_Error("Opening a read/write session failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }


    crv = pFunctionList->C_Login(hRwSession, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Login with correct password succeeded\n");
    } else {
        PKM_Error("C_Login with correct password failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate an AES key ... \n");
    /* generate an AES Secret Key */
    crv = pFunctionList->C_GenerateKey(hRwSession, &sAESKeyMech,
                                       sAESKeyTemplate,
                                       NUM_ELEM(sAESKeyTemplate),
                                       &hAESSecKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateKey AES succeeded\n");
    } else {
        PKM_Error("C_GenerateKey AES failed with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate a RSA key pair ... \n");
    /*** GEN RSA Key ***/
    crv = pFunctionList->C_GenerateKeyPair(hRwSession, &rsaKeyPairGenMech,
                                           rsaPubKeyTemplate,
                                           NUM_ELEM(rsaPubKeyTemplate),
                                           rsaPrivKeyTemplate,
                                           NUM_ELEM(rsaPrivKeyTemplate),
                                           &hRSApubKey, &hRSAprivKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateKeyPair created an RSA key pair. \n");
    } else {
        PKM_Error("C_GenerateKeyPair failed to create an RSA key pair.\n"
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("**** Generation of keys completed ***** \n");

    PKM_LogIt("**** Forcing Error State ****\n");
    for (i=0; i < sizeof bigRandomData; i++) {
	bigRandomData[i] = i & 0xff;
    }
    /* We force an error state by trying to generate a single random value greater then the drbg limit. */
    crv = pFunctionList->C_GenerateRandom(hRwSession,
                                          bigRandomData, sizeof bigRandomData);
    if (crv != CKR_OK) {
        PKM_LogIt("C_GenerateRandom expected failure with 32K requested error"
                  "0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
    } else {
        PKM_Error("C_GenerateRandom incorrectly generated 32K of data\n");
        return CKR_DEVICE_ERROR;
    }

    /* make sure we didn't actually output anything */
#define CHECK_DATA(function, data, len) { \
    int j; \
    for (j=0; j < len; j++) { \
	if (bigRandomData[j] != (j & 0xff)) { \
	    PKM_Error(#function " outputed data in error\n"); \
	    return CKR_DEVICE_ERROR; \
	} \
    } }
    

#define ERROR_STATE_CHECK(crv,function) \
    if (crv == CKR_DEVICE_ERROR) { \
        PKM_LogIt(#function " correctly failed in error state\n"); \
    } else if (crv == CKR_OK) { \
        PKM_Error(#function " incorrectly succeeded in error state\n"); \
	return CKR_DEVICE_ERROR; \
    } else { \
        PKM_Error(#function " failed incorrect error codewith 0x%08X, %-26s\n", \
                  crv, PKM_CK_RVtoStr(crv)); \
        return crv; \
    }
    CHECK_DATA(C_GenerateRandom, bigRandomData, sizeof bigRandomData);


    /* we should now be in error state, the following functions should still work fine: 
     *   FC_GetInfo, FG_GetSlotList, FC_GetSlotInfo, FC_GetTokenInfo, FC_Close_Session, 
     *   FC_CloseAllSessions, FC_Finalize
     *   FC_Initialize, FC_InitToken, FC_WaitForSlotEvent, FC_GetFunctionList
     *   All other functions should fail with CKR_DEVICE_ERROR. Test all the output functions.
     */
    crv = pFunctionList->C_GetMechanismList(pSlotList[slotID],
                                            NULL, &dummyULong);
    ERROR_STATE_CHECK(crv,C_GetMechanismList)
    crv = pFunctionList->C_GetMechanismInfo(pSlotList[slotID], 
					CKM_RSA_PKCS, &minfo);
    ERROR_STATE_CHECK(crv,C_GetMechanismInfo)
    crv = pFunctionList->C_SetPIN(hRwSession, pwd, pwdLen, pwd, pwdLen);
    ERROR_STATE_CHECK(crv,C_SetPIN)
    crv = pFunctionList->C_OpenSession(pSlotList[slotID],
                                       CKF_RW_SESSION | CKF_SERIAL_SESSION,
                                       NULL, NULL, &dummyULong);
    ERROR_STATE_CHECK(crv,C_OpenSession)
    crv = pFunctionList->C_GetSessionInfo(hRwSession, &sess_info);
    ERROR_STATE_CHECK(crv,C_GetSessionInfo)
    dummyULong = sizeof bigRandomData;
    crv = pFunctionList->C_GetOperationState(hRwSession, bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_GetOperationState)
    CHECK_DATA(C_GetOperaionState, bigRandomData, sizeof bigRandomData);
    crv = pFunctionList->C_SetOperationState(hRwSession, bigRandomData, 
					     dummyULong, 0, 0);
    ERROR_STATE_CHECK(crv,C_SetOperationState)
    crv = pFunctionList->C_Login(hRwSession, CKU_USER, pwd, pwdLen);
    ERROR_STATE_CHECK(crv,C_Login)
    crv = pFunctionList->C_CreateObject(hRwSession, sAESKeyTemplate,
		 NUM_ELEM(sAESKeyTemplate), &dummyULong);
    ERROR_STATE_CHECK(crv,C_CreateObject)
    crv = pFunctionList->C_CopyObject(hRwSession, hAESSecKey, 
					NULL, 0, &dummyULong);
    ERROR_STATE_CHECK(crv,C_CopyObject)
    crv = pFunctionList->C_DestroyObject(hRwSession, dummyULong);
    ERROR_STATE_CHECK(crv,C_DestroyObject)
    crv = pFunctionList->C_GetObjectSize(hRwSession, hAESSecKey, &dummyULong);
    ERROR_STATE_CHECK(crv,C_GetObjectSize)
    crv = pFunctionList->C_GetAttributeValue(hRwSession, hAESSecKey,
    			sAESKeyTemplate,NUM_ELEM(sAESKeyTemplate));
    ERROR_STATE_CHECK(crv,C_GetAttributeValue)
    crv = pFunctionList->C_SetAttributeValue(hRwSession, hAESSecKey,
    			sAESKeyTemplate,NUM_ELEM(sAESKeyTemplate));
    ERROR_STATE_CHECK(crv,C_SetAttributeValue)
    crv = pFunctionList->C_FindObjectsInit(hRwSession, NULL, 0);
    ERROR_STATE_CHECK(crv,C_FindObjectsInit)
    crv = pFunctionList->C_FindObjects(hRwSession, &dummyULong, 1, &dummyULong2);
    ERROR_STATE_CHECK(crv,C_FindObjects)
    crv = pFunctionList->C_FindObjectsFinal(hRwSession);
    ERROR_STATE_CHECK(crv,C_FindObjectsFinal)

    crv = pFunctionList->C_EncryptInit(hRwSession, &mech_AES_CBC, hAESSecKey);
    ERROR_STATE_CHECK(crv,C_EncryptInit)
    dummyULong = sizeof(bigRandomData);
    crv = pFunctionList->C_EncryptUpdate(hRwSession, bigRandomData,
                                         64, bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_EncryptUpdate)
    CHECK_DATA(C_EncryptUpdate, bigRandomData, sizeof bigRandomData);
    dummyULong = sizeof(bigRandomData);
    crv = pFunctionList->C_EncryptFinal(hRwSession, bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_EncryptFinal)
    CHECK_DATA(C_EncryptFinal, bigRandomData, sizeof bigRandomData);
    crv = pFunctionList->C_EncryptInit(hRwSession, &mech_AES_CBC, hAESSecKey);
    ERROR_STATE_CHECK(crv,C_EncryptInit)
    crv = pFunctionList->C_Encrypt(hRwSession, bigRandomData,
                                         64, bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_Encrypt)
    CHECK_DATA(C_Encrypt, bigRandomData, sizeof bigRandomData);

    crv = pFunctionList->C_DecryptInit(hRwSession, &mech_AES_CBC, hAESSecKey);
    ERROR_STATE_CHECK(crv,C_DecryptInit)
    dummyULong = sizeof(bigRandomData);
    crv = pFunctionList->C_DecryptUpdate(hRwSession, bigRandomData,
                                         64, bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_DecryptUpdate)
    CHECK_DATA(C_DecryptUpdate, bigRandomData, sizeof bigRandomData);
    dummyULong = sizeof(bigRandomData);
    crv = pFunctionList->C_DecryptFinal(hRwSession, bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_DecryptFinal)
    CHECK_DATA(C_DecryptFinal, bigRandomData, sizeof bigRandomData);
    crv = pFunctionList->C_DecryptInit(hRwSession, &mech_AES_CBC, hAESSecKey);
    ERROR_STATE_CHECK(crv,C_DecryptInit)
    crv = pFunctionList->C_Decrypt(hRwSession, bigRandomData,
                                         64, bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_Decrypt)
    CHECK_DATA(C_Decrypt, bigRandomData, sizeof bigRandomData);

    /* digest & combined functions */
    crv = pFunctionList->C_DigestInit(hRwSession, &mech_SHA_256);
    ERROR_STATE_CHECK(crv,C_DigestInit)
    crv = pFunctionList->C_DigestUpdate(hRwSession, bigRandomData, 64);
    ERROR_STATE_CHECK(crv,C_DigestUpdate)
    crv = pFunctionList->C_DigestKey(hRwSession, hAESSecKey);
    ERROR_STATE_CHECK(crv,C_DigestKey)
    dummyULong = sizeof bigRandomData;
    crv = pFunctionList->C_EncryptInit(hRwSession, &mech_AES_CBC, hAESSecKey);
    ERROR_STATE_CHECK(crv,C_EncryptInit)
    crv = pFunctionList->C_DigestEncryptUpdate(hRwSession, bigRandomData, 64,
                                               bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_DigestEncryptUpdate)
    CHECK_DATA(C_DigestEncryptUpdate, bigRandomData, sizeof bigRandomData);
    dummyULong = sizeof bigRandomData;
    crv = pFunctionList->C_DecryptInit(hRwSession, &mech_AES_CBC, hAESSecKey);
    ERROR_STATE_CHECK(crv,C_DecryptInit)
    crv = pFunctionList->C_DecryptDigestUpdate(hRwSession, bigRandomData, 64,
                                               bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_DecryptDigestUpdate)
    CHECK_DATA(C_DecryptDigestUpdate, bigRandomData, sizeof bigRandomData);
    dummyULong = sizeof bigRandomData;
    crv = pFunctionList->C_DigestFinal(hRwSession, bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_DigestFinal)
    CHECK_DATA(C_DigestFinal, bigRandomData, sizeof bigRandomData);
    crv = pFunctionList->C_DigestInit(hRwSession, &mech_SHA_256);
    ERROR_STATE_CHECK(crv,C_DigestInit)
    dummyULong = sizeof bigRandomData;
    crv = pFunctionList->C_Digest(hRwSession, bigRandomData, 64,
                                  bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_Digest)
    CHECK_DATA(C_Digest, bigRandomData, sizeof bigRandomData);

    /* Sign/Verify */
    crv = pFunctionList->C_SignInit(hRwSession, &rsaMech, hRSAprivKey);
    ERROR_STATE_CHECK(crv,C_SignInit)
    dummyULong = sizeof bigRandomData;
    crv = pFunctionList->C_Sign(hRwSession, bigRandomData, 64,
				bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_Sign)
    CHECK_DATA(C_Sign, bigRandomData, sizeof bigRandomData);

    crv = pFunctionList->C_VerifyInit(hRwSession, &rsaMech, hRSApubKey);
    ERROR_STATE_CHECK(crv,C_VerifyInit)
    crv = pFunctionList->C_Verify(hRwSession, bigRandomData, RSA_BITS/8,
                                  bigRandomData, 64);
    ERROR_STATE_CHECK(crv,C_Verify)

    crv = pFunctionList->C_SignRecoverInit(hRwSession, &rsaMech, hRSAprivKey);
    ERROR_STATE_CHECK(crv,C_SignRecoverInit)
    dummyULong = sizeof bigRandomData;
    crv = pFunctionList->C_SignRecover(hRwSession, bigRandomData, 64,
				bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_SignRecover)
    CHECK_DATA(C_SignRecover, bigRandomData, sizeof bigRandomData);

    crv = pFunctionList->C_VerifyRecoverInit(hRwSession, &rsaMech, hRSApubKey);
    ERROR_STATE_CHECK(crv,C_VerifyRecoverInit)
    dummyULong = sizeof bigRandomData;
    crv = pFunctionList->C_VerifyRecover(hRwSession, bigRandomData, RSA_BITS/8,
                                  bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_VerifyRecover)
    CHECK_DATA(C_VerifyRecover, bigRandomData, sizeof bigRandomData);

    crv = pFunctionList->C_SignInit(hRwSession, &mech_SHA_256_hmac, hAESSecKey);
    ERROR_STATE_CHECK(crv,C_SignInit)
    crv = pFunctionList->C_SignUpdate(hRwSession, bigRandomData, 64);
    ERROR_STATE_CHECK(crv,C_SignUpdate)
    dummyULong = sizeof bigRandomData;
    crv = pFunctionList->C_SignFinal(hRwSession, bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_SignFinal)

    crv = pFunctionList->C_VerifyInit(hRwSession, &mech_SHA_256_hmac, 
				     hAESSecKey);
    ERROR_STATE_CHECK(crv,C_VerifyInit)
    crv = pFunctionList->C_VerifyUpdate(hRwSession, bigRandomData, 64);
    ERROR_STATE_CHECK(crv,C_VerifyUpdate)
    crv = pFunctionList->C_VerifyFinal(hRwSession, bigRandomData, RSA_BITS/8);
    ERROR_STATE_CHECK(crv,C_VerifyFinal)

    /* Key Management */
    crv = pFunctionList->C_GenerateKey(hRwSession, &sAESKeyMech,
                                       sAESKeyTemplate,
                                       NUM_ELEM(sAESKeyTemplate),
                                       &dummyULong);
    ERROR_STATE_CHECK(crv,C_GenerateKey);
    crv = pFunctionList->C_GenerateKeyPair(hRwSession, &rsaKeyPairGenMech,
                                           rsaPubKeyTemplate,
                                           NUM_ELEM(rsaPubKeyTemplate),
                                           rsaPrivKeyTemplate,
                                           NUM_ELEM(rsaPrivKeyTemplate),
                                           &dummyULong, &dummyULong2);
    ERROR_STATE_CHECK(crv,C_GenerateKeyPair);
    dummyULong = sizeof(bigRandomData);
    crv = pFunctionList->C_WrapKey(
        hRwSession, &rsaMech,
        hRSApubKey, hAESSecKey,
        bigRandomData, &dummyULong);
    ERROR_STATE_CHECK(crv,C_WrapKey);
    CHECK_DATA(C_WrapKey, bigRandomData, sizeof bigRandomData);
    crv = pFunctionList->C_UnwrapKey(
        hRwSession, &rsaMech, hRSAprivKey,
        bigRandomData, sizeof bigRandomData, sAESKeyTemplate,
        NUM_ELEM(sAESKeyTemplate),
       &dummyULong);
    ERROR_STATE_CHECK(crv,C_UnwrapKey);
    crv = pFunctionList->C_DeriveKey(hRwSession, &tls_mech, hAESSecKey, NULL, 0,
                                     &dummyULong);
    ERROR_STATE_CHECK(crv,C_DeriveKey);

    /* rng */
    crv = pFunctionList->C_SeedRandom(hRwSession, bigRandomData, 32);
    ERROR_STATE_CHECK(crv,C_SeedRandom);
    crv = pFunctionList->C_GenerateRandom(hRwSession, bigRandomData, 32);
    ERROR_STATE_CHECK(crv,C_GenerateRandom);

    crv = pFunctionList->C_Logout(hRwSession);
    ERROR_STATE_CHECK(crv,C_Logout)

    crv = pFunctionList->C_CloseSession(hRwSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    return crv;
}

/* PKM_HybridMode                                                         */
/* The NSS cryptographic module has two modes of operation: FIPS Approved */
/* mode and NONFIPS Approved mode. The two modes of operation are         */
/* independent of each other -- they have their own copies of data        */
/* structures and they are even allowed to be active at the same time.    */
/* The module is FIPS 140-2 compliant only when the NONFIPS mode          */
/* is inactive.                                                           */
/* PKM_HybridMode demostrates how an application can switch between the   */
/* two modes: FIPS Approved mode and NONFIPS mode.                        */
CK_RV
PKM_HybridMode(CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen,
               CK_C_INITIALIZE_ARGS_NSS *initArgs)
{

    CK_FUNCTION_LIST_PTR pC_FunctionList;
    CK_SLOT_ID *pC_SlotList = NULL;
    CK_ULONG slotID_C = 1;
    CK_FUNCTION_LIST_PTR pFC_FunctionList;
    CK_SLOT_ID *pFC_SlotList = NULL;
    CK_ULONG slotID_FC = 0;
    CK_RV crv = CKR_OK;
    CK_SESSION_HANDLE hSession;
    int origMode = MODE; /* remember the orginal MODE value */

    PKM_LogIt("PKM_HybridMode started\n");
    NUMTESTS++; /* increment NUMTESTS */
    MODE = NONFIPSMODE;

    PKM_LogIt("loading C_GetFunctionList for Non FIPS Mode; slotID %d \n",
              slotID_C);
    crv = PKM_GetFunctionList("C_GetFunctionList", &pC_FunctionList);
    if (crv != CKR_OK) {
	PKM_Error("Could not get the function list for softokn3 0x%08X %-26s\n",
		crv, PKM_CK_RVtoStr(crv));
	return crv;
    }

    /* invoke C_Initialize as pC_FunctionList->C_Initialize */
    crv = pC_FunctionList->C_Initialize(initArgs);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Initialize succeeded\n");
    } else {
        PKM_Error("C_Initialize failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    pC_SlotList = PKM_GetSlotList(pC_FunctionList, slotID_C);
    if (pC_SlotList == NULL) {
        PKM_Error("PKM_GetSlotList failed with \n");
        return crv;
    }
    crv = pC_FunctionList->C_OpenSession(pC_SlotList[slotID_C],
                                         CKF_SERIAL_SESSION,
                                         NULL, NULL, &hSession);
    if (crv == CKR_OK) {
        PKM_LogIt("NONFIPS C_OpenSession succeeded\n");
    } else {
        PKM_Error("C_OpenSession failed for NONFIPS token "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pC_FunctionList->C_Login(hSession, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("able to login in NONFIPS token\n");
    } else {
        PKM_Error("Unable to login in to NONFIPS token "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pC_FunctionList->C_Logout(hSession);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Logout succeeded\n");
    } else {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_ShowInfo(pC_FunctionList, slotID_C);
    MODE = HYBRIDMODE;

    /* Now load the FIPS token */
    /* FIPS mode == FC_GetFunctionList */
    PKM_LogIt("loading FC_GetFunctionList for FIPS Mode; slotID %d \n",
              slotID_FC);
    crv = PKM_GetFunctionList("FC_GetFunctionList", &pFC_FunctionList);
    if (crv != CKR_OK) {
        PKM_Error("GetFunctionList failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("pFC_FunctionList->C_Foo == pFC_FunctionList->FC_Foo\n");

    /* invoke FC_Initialize as pFunctionList->C_Initialize */
    crv = pFC_FunctionList->C_Initialize(initArgs);
    if (crv == CKR_OK) {
        PKM_LogIt("FC_Initialize succeeded\n");
    } else {
        PKM_Error("FC_Initialize failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    PKM_ShowInfo(pFC_FunctionList, slotID_FC);

    pFC_SlotList = PKM_GetSlotList(pFC_FunctionList, slotID_FC);
    if (pFC_SlotList == NULL) {
        PKM_Error("PKM_GetSlotList failed with \n");
        return crv;
    }

    crv = pC_FunctionList->C_Login(hSession, CKU_USER, pwd, pwdLen);
    if (crv != CKR_OK) {
        PKM_LogIt("NONFIPS token cannot log in when FIPS token is loaded\n");
    } else {
        PKM_Error("Able to login in to NONFIPS token\n");
        return CKR_USER_ALREADY_LOGGED_IN;
    }
    crv = pC_FunctionList->C_CloseSession(hSession);
    if (crv == CKR_OK) {
        PKM_LogIt("NONFIPS pC_CloseSession succeeded\n");
    } else {
        PKM_Error("pC_CloseSession failed for NONFIPS token "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("The module is FIPS 140-2 compliant\n"
              "only when the NONFIPS Approved mode is inactive by \n"
              "calling C_Finalize on the NONFIPS token.\n");

    /* to go in FIPSMODE you must Finalize the NONFIPS mode pointer */
    crv = pC_FunctionList->C_Finalize(NULL);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Finalize of NONFIPS Token succeeded\n");
        MODE = FIPSMODE;
    } else {
        PKM_Error("C_Finalize of NONFIPS Token failed with "
                  "0x%08X, %-26s\n",
                  crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("*** In FIPS mode!  ***\n");

    /* could do some operations in FIPS MODE */

    crv = pFC_FunctionList->C_Finalize(NULL);
    if (crv == CKR_OK) {
        PKM_LogIt("Exiting FIPSMODE by caling FC_Finalize.\n");
        MODE = NOMODE;
    } else {
        PKM_Error("FC_Finalize failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    if (pC_SlotList)
        free(pC_SlotList);
    if (pFC_SlotList)
        free(pFC_SlotList);

    MODE = origMode; /* set the mode back to the orginal Mode value */
    PKM_LogIt("PKM_HybridMode test Completed\n\n");
    return crv;
}

CK_RV
PKM_Mechanism(CK_FUNCTION_LIST_PTR pFunctionList,
              CK_SLOT_ID *pSlotList, CK_ULONG slotID)
{

    CK_RV crv = CKR_OK;
    CK_MECHANISM_TYPE *pMechanismList;
    CK_ULONG mechanismCount;
    CK_ULONG i;
    const char *mechName = NULL;

    PKM_LogIt("PKM_Mechanism started\n");
    NUMTESTS++; /* increment NUMTESTS */

    /* Get the mechanism list */
    crv = pFunctionList->C_GetMechanismList(pSlotList[slotID],
                                            NULL, &mechanismCount);
    if (crv != CKR_OK) {
        PKM_Error("C_GetMechanismList failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    PKM_LogIt("C_GetMechanismList reported there are %lu mechanisms\n",
              mechanismCount);
    pMechanismList = (CK_MECHANISM_TYPE *)
        malloc(mechanismCount * sizeof(CK_MECHANISM_TYPE));
    if (!pMechanismList) {
        PKM_Error("failed to allocate mechanism list\n");
        return crv;
    }
    crv = pFunctionList->C_GetMechanismList(pSlotList[slotID],
                                            pMechanismList, &mechanismCount);
    if (crv != CKR_OK) {
        PKM_Error("C_GetMechanismList failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    PKM_LogIt("C_GetMechanismList returned the mechanism types:\n");
    if (verbose) {
        for (i = 0; i < mechanismCount; i++) {
            mechName = getName(pMechanismList[(i)], ConstMechanism);

            /* output two mechanism name on each line */
            /* currently the longest known mechansim name length is 37 */
            if (mechName) {
                printf("%-40s", mechName);
            } else {
                printf("Unknown mechanism: 0x%08lX ", pMechanismList[i]);
            }
            if ((i % 2) == 1)
                printf("\n");
        }
        printf("\n\n");
    }

    for (i = 0; i < mechanismCount; i++) {
        CK_MECHANISM_INFO minfo;

        memset(&minfo, 0, sizeof(CK_MECHANISM_INFO));
        crv = pFunctionList->C_GetMechanismInfo(pSlotList[slotID],
                                                pMechanismList[i], &minfo);
        if (CKR_OK != crv) {
            PKM_Error("C_GetMechanismInfo(%lu, %lu) returned 0x%08X, %-26s\n",
                      pSlotList[slotID], pMechanismList[i], crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }

        mechName = getName(pMechanismList[i], ConstMechanism);
        if (!mechName)
            mechName = "Unknown mechanism";
        PKM_LogIt("    [%lu]: CK_MECHANISM_TYPE = %s 0x%08lX\n", (i + 1),
                  mechName,
                  pMechanismList[i]);
        PKM_LogIt("    ulMinKeySize = %lu\n", minfo.ulMinKeySize);
        PKM_LogIt("    ulMaxKeySize = %lu\n", minfo.ulMaxKeySize);
        PKM_LogIt("    flags = 0x%08x\n", minfo.flags);
        PKM_LogIt("        -> HW = %s\n", minfo.flags & CKF_HW ? "TRUE"
                                                               : "FALSE");
        PKM_LogIt("        -> ENCRYPT = %s\n", minfo.flags & CKF_ENCRYPT ? "TRUE"
                                                                         : "FALSE");
        PKM_LogIt("        -> DECRYPT = %s\n", minfo.flags & CKF_DECRYPT ? "TRUE"
                                                                         : "FALSE");
        PKM_LogIt("        -> DIGEST = %s\n", minfo.flags & CKF_DIGEST ? "TRUE"
                                                                       : "FALSE");
        PKM_LogIt("        -> SIGN = %s\n", minfo.flags & CKF_SIGN ? "TRUE"
                                                                   : "FALSE");
        PKM_LogIt("        -> SIGN_RECOVER = %s\n", minfo.flags &
                                                            CKF_SIGN_RECOVER
                                                        ? "TRUE"
                                                        : "FALSE");
        PKM_LogIt("        -> VERIFY = %s\n", minfo.flags & CKF_VERIFY ? "TRUE"
                                                                       : "FALSE");
        PKM_LogIt("        -> VERIFY_RECOVER = %s\n",
                  minfo.flags & CKF_VERIFY_RECOVER ? "TRUE" : "FALSE");
        PKM_LogIt("        -> GENERATE = %s\n", minfo.flags & CKF_GENERATE ? "TRUE"
                                                                           : "FALSE");
        PKM_LogIt("        -> GENERATE_KEY_PAIR = %s\n",
                  minfo.flags & CKF_GENERATE_KEY_PAIR ? "TRUE" : "FALSE");
        PKM_LogIt("        -> WRAP = %s\n", minfo.flags & CKF_WRAP ? "TRUE"
                                                                   : "FALSE");
        PKM_LogIt("        -> UNWRAP = %s\n", minfo.flags & CKF_UNWRAP ? "TRUE"
                                                                       : "FALSE");
        PKM_LogIt("        -> DERIVE = %s\n", minfo.flags & CKF_DERIVE ? "TRUE"
                                                                       : "FALSE");
        PKM_LogIt("        -> EXTENSION = %s\n", minfo.flags & CKF_EXTENSION ? "TRUE"
                                                                             : "FALSE");

        PKM_LogIt("\n");
    }

    return crv;
}

CK_RV
PKM_RNG(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID *pSlotList,
        CK_ULONG slotID)
{
    CK_SESSION_HANDLE hSession;
    CK_RV crv = CKR_OK;
    CK_BYTE randomData[16];
    CK_BYTE seed[] = { 0x01, 0x03, 0x35, 0x55, 0xFF };

    PKM_LogIt("PKM_RNG started\n");
    NUMTESTS++; /* increment NUMTESTS */

    crv = pFunctionList->C_OpenSession(pSlotList[slotID], CKF_SERIAL_SESSION,
                                       NULL, NULL, &hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_OpenSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_GenerateRandom(hSession,
                                          randomData, sizeof randomData);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateRandom without login succeeded\n");
    } else {
        PKM_Error("C_GenerateRandom without login failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_SeedRandom(hSession, seed, sizeof(seed));
    if (crv == CKR_OK) {
        PKM_LogIt("C_SeedRandom without login succeeded\n");
    } else {
        PKM_Error("C_SeedRandom without login failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_GenerateRandom(hSession,
                                          randomData, sizeof randomData);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateRandom without login succeeded\n");
    } else {
        PKM_Error("C_GenerateRandom without login failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_CloseSession(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    return crv;
}

CK_RV
PKM_SessionLogin(CK_FUNCTION_LIST_PTR pFunctionList,
                 CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                 CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen)
{
    CK_SESSION_HANDLE hSession;
    CK_RV crv = CKR_OK;

    PKM_LogIt("PKM_SessionLogin started\n");
    NUMTESTS++; /* increment NUMTESTS */

    crv = pFunctionList->C_OpenSession(pSlotList[slotID], CKF_SERIAL_SESSION,
                                       NULL, NULL, &hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_OpenSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_Login(hSession, CKU_USER, (unsigned char *)"netscape", 8);
    if (crv == CKR_OK) {
        PKM_Error("C_Login with wrong password succeeded\n");
        return CKR_FUNCTION_FAILED;
    } else {
        PKM_LogIt("As expected C_Login with wrong password returned 0x%08X, "
                  "%-26s.\n ",
                  crv, PKM_CK_RVtoStr(crv));
    }
    crv = pFunctionList->C_Login(hSession, CKU_USER, (unsigned char *)"red hat", 7);
    if (crv == CKR_OK) {
        PKM_Error("C_Login with wrong password succeeded\n");
        return CKR_FUNCTION_FAILED;
    } else {
        PKM_LogIt("As expected C_Login with wrong password returned 0x%08X, "
                  "%-26s.\n ",
                  crv, PKM_CK_RVtoStr(crv));
    }
    crv = pFunctionList->C_Login(hSession, CKU_USER,
                                 (unsigned char *)"sun", 3);
    if (crv == CKR_OK) {
        PKM_Error("C_Login with wrong password succeeded\n");
        return CKR_FUNCTION_FAILED;
    } else {
        PKM_LogIt("As expected C_Login with wrong password returned 0x%08X, "
                  "%-26s.\n ",
                  crv, PKM_CK_RVtoStr(crv));
    }
    crv = pFunctionList->C_Login(hSession, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Login with correct password succeeded\n");
    } else {
        PKM_Error("C_Login with correct password failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_Logout(hSession);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Logout succeeded\n");
    } else {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_CloseSession(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    return crv;
}

/*
* PKM_LegacyFunctions
*
* Legacyfunctions exist only for backwards compatibility.
* C_GetFunctionStatus and C_CancelFunction functions were
* meant for managing parallel execution of cryptographic functions.
*
* C_GetFunctionStatus is a legacy function which should simply return
* the value CKR_FUNCTION_NOT_PARALLEL.
*
* C_CancelFunction is a legacy function which should simply return the
* value CKR_FUNCTION_NOT_PARALLEL.
*
*/
CK_RV
PKM_LegacyFunctions(CK_FUNCTION_LIST_PTR pFunctionList,
                    CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                    CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen)
{
    CK_SESSION_HANDLE hSession;
    CK_RV crv = CKR_OK;

    PKM_LogIt("PKM_LegacyFunctions started\n");
    NUMTESTS++; /* increment NUMTESTS */

    crv = pFunctionList->C_OpenSession(pSlotList[slotID], CKF_SERIAL_SESSION,
                                       NULL, NULL, &hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_OpenSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_Login(hSession, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Login with correct password succeeded\n");
    } else {
        PKM_Error("C_Login with correct password failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_GetFunctionStatus(hSession);
    if (crv == CKR_FUNCTION_NOT_PARALLEL) {
        PKM_LogIt("C_GetFunctionStatus correctly"
                  "returned CKR_FUNCTION_NOT_PARALLEL \n");
    } else {
        PKM_Error("C_GetFunctionStatus failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_CancelFunction(hSession);
    if (crv == CKR_FUNCTION_NOT_PARALLEL) {
        PKM_LogIt("C_CancelFunction correctly "
                  "returned CKR_FUNCTION_NOT_PARALLEL \n");
    } else {
        PKM_Error("C_CancelFunction failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_Logout(hSession);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Logout succeeded\n");
    } else {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_CloseSession(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    return crv;
}

/*
*  PKM_DualFuncDigest - demostrates the Dual-function
*  cryptograpic functions:
*
*   C_DigestEncryptUpdate - multi-part Digest and Encrypt
*   C_DecryptDigestUpdate - multi-part Decrypt and Digest
*
*
*/

CK_RV
PKM_DualFuncDigest(CK_FUNCTION_LIST_PTR pFunctionList,
                   CK_SESSION_HANDLE hSession,
                   CK_OBJECT_HANDLE hSecKey, CK_MECHANISM *cryptMech,
                   CK_OBJECT_HANDLE hSecKeyDigest,
                   CK_MECHANISM *digestMech,
                   const CK_BYTE *pData, CK_ULONG pDataLen)
{
    CK_RV crv = CKR_OK;
    CK_BYTE eDigest[MAX_DIGEST_SZ];
    CK_BYTE dDigest[MAX_DIGEST_SZ];
    CK_ULONG ulDigestLen;
    CK_BYTE ciphertext[MAX_CIPHER_SZ];
    CK_ULONG ciphertextLen, lastLen;
    CK_BYTE plaintext[MAX_DATA_SZ];
    CK_ULONG plaintextLen;
    unsigned int i;

    memset(eDigest, 0, sizeof(eDigest));
    memset(dDigest, 0, sizeof(dDigest));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(plaintext, 0, sizeof(plaintext));

    PKM_LogIt("PKM_DualFuncDigest started\n");
    NUMTESTS++; /* increment NUMTESTS */

    /*
     * First init the Digest and Ecrypt operations
     */
    crv = pFunctionList->C_EncryptInit(hSession, cryptMech, hSecKey);
    if (crv != CKR_OK) {
        PKM_Error("C_EncryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_DigestInit(hSession, digestMech);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    ciphertextLen = sizeof(ciphertext);
    crv = pFunctionList->C_DigestEncryptUpdate(hSession, (CK_BYTE *)pData,
                                               pDataLen,
                                               ciphertext, &ciphertextLen);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestEncryptUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    ulDigestLen = sizeof(eDigest);
    crv = pFunctionList->C_DigestFinal(hSession, eDigest, &ulDigestLen);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* get the last piece of ciphertext (length should be 0 */
    lastLen = sizeof(ciphertext) - ciphertextLen;
    crv = pFunctionList->C_EncryptFinal(hSession,
                                        (CK_BYTE *)&ciphertext[ciphertextLen],
                                        &lastLen);
    if (crv != CKR_OK) {
        PKM_Error("C_EncryptFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    ciphertextLen = ciphertextLen + lastLen;
    if (verbose) {
        printf("ciphertext = ");
        for (i = 0; i < ciphertextLen; i++) {
            printf("%02x", (unsigned)ciphertext[i]);
        }
        printf("\n");
        printf("eDigest = ");
        for (i = 0; i < ulDigestLen; i++) {
            printf("%02x", (unsigned)eDigest[i]);
        }
        printf("\n");
    }

    /* Decrypt the text */
    crv = pFunctionList->C_DecryptInit(hSession, cryptMech, hSecKey);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_DigestInit(hSession, digestMech);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    plaintextLen = sizeof(plaintext);
    crv = pFunctionList->C_DecryptDigestUpdate(hSession, ciphertext,
                                               ciphertextLen,
                                               plaintext,
                                               &plaintextLen);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptDigestUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    lastLen = sizeof(plaintext) - plaintextLen;

    crv = pFunctionList->C_DecryptFinal(hSession,
                                        (CK_BYTE *)&plaintext[plaintextLen],
                                        &lastLen);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    plaintextLen = plaintextLen + lastLen;

    ulDigestLen = sizeof(dDigest);
    crv = pFunctionList->C_DigestFinal(hSession, dDigest, &ulDigestLen);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    if (plaintextLen != pDataLen) {
        PKM_Error("plaintextLen is %lu\n", plaintextLen);
        return crv;
    }

    if (verbose) {
        printf("plaintext = ");
        for (i = 0; i < plaintextLen; i++) {
            printf("%02x", (unsigned)plaintext[i]);
        }
        printf("\n");
        printf("dDigest = ");
        for (i = 0; i < ulDigestLen; i++) {
            printf("%02x", (unsigned)dDigest[i]);
        }
        printf("\n");
    }

    if (memcmp(eDigest, dDigest, ulDigestLen) == 0) {
        PKM_LogIt("Encrypted Digest equals Decrypted Digest\n");
    } else {
        PKM_Error("Digests don't match\n");
    }

    if ((plaintextLen == pDataLen) &&
        (memcmp(plaintext, pData, pDataLen)) == 0) {
        PKM_LogIt("DualFuncDigest decrypt test case passed\n");
    } else {
        PKM_Error("DualFuncDigest derypt test case failed\n");
    }

    return crv;
}

/*
* PKM_SecKeyCrypt - Symmetric key encrypt/decyprt
*
*/

CK_RV
PKM_SecKeyCrypt(CK_FUNCTION_LIST_PTR pFunctionList,
                CK_SESSION_HANDLE hSession,
                CK_OBJECT_HANDLE hSymKey, CK_MECHANISM *cryptMech,
                const CK_BYTE *pData, CK_ULONG dataLen)
{
    CK_RV crv = CKR_OK;

    CK_BYTE cipher1[MAX_CIPHER_SZ];
    CK_BYTE cipher2[MAX_CIPHER_SZ];
    CK_BYTE data1[MAX_DATA_SZ];
    CK_BYTE data2[MAX_DATA_SZ];
    CK_ULONG cipher1Len = 0, cipher2Len = 0, lastLen = 0;
    CK_ULONG data1Len = 0, data2Len = 0;

    PKM_LogIt("PKM_SecKeyCrypt started\n");
    NUMTESTS++; /* increment NUMTESTS */

    memset(cipher1, 0, sizeof(cipher1));
    memset(cipher2, 0, sizeof(cipher2));
    memset(data1, 0, sizeof(data1));
    memset(data2, 0, sizeof(data2));

    /* C_Encrypt */
    crv = pFunctionList->C_EncryptInit(hSession, cryptMech, hSymKey);
    if (crv != CKR_OK) {
        PKM_Error("C_EncryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    cipher1Len = sizeof(cipher1);
    crv = pFunctionList->C_Encrypt(hSession, (CK_BYTE *)pData, dataLen,
                                   cipher1, &cipher1Len);
    if (crv != CKR_OK) {
        PKM_Error("C_Encrypt failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* C_EncryptUpdate */
    crv = pFunctionList->C_EncryptInit(hSession, cryptMech, hSymKey);
    if (crv != CKR_OK) {
        PKM_Error("C_EncryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    cipher2Len = sizeof(cipher2);
    crv = pFunctionList->C_EncryptUpdate(hSession, (CK_BYTE *)pData,
                                         dataLen,
                                         cipher2, &cipher2Len);
    if (crv != CKR_OK) {
        PKM_Error("C_EncryptUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    lastLen = sizeof(cipher2) - cipher2Len;

    crv = pFunctionList->C_EncryptFinal(hSession,
                                        (CK_BYTE *)&cipher2[cipher2Len],
                                        &lastLen);
    cipher2Len = cipher2Len + lastLen;

    if ((cipher1Len == cipher2Len) &&
        (memcmp(cipher1, cipher2, sizeof(cipher1Len)) == 0)) {
        PKM_LogIt("encrypt test case passed\n");
    } else {
        PKM_Error("encrypt test case failed\n");
        return CKR_GENERAL_ERROR;
    }

    /* C_Decrypt */
    crv = pFunctionList->C_DecryptInit(hSession, cryptMech, hSymKey);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    data1Len = sizeof(data1);
    crv = pFunctionList->C_Decrypt(hSession, cipher1, cipher1Len,
                                   data1, &data1Len);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    /* now use C_DecryptUpdate the text */
    crv = pFunctionList->C_DecryptInit(hSession, cryptMech, hSymKey);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    data2Len = sizeof(data2);
    crv = pFunctionList->C_DecryptUpdate(hSession, cipher2,
                                         cipher2Len,
                                         data2, &data2Len);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    lastLen = sizeof(data2) - data2Len;
    crv = pFunctionList->C_DecryptFinal(hSession,
                                        (CK_BYTE *)&data2[data2Len],
                                        &lastLen);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    data2Len = data2Len + lastLen;

    /* Comparison of Decrypt data */

    if ((data1Len == data2Len) && (dataLen == data1Len) &&
        (memcmp(data1, pData, dataLen) == 0) &&
        (memcmp(data2, pData, dataLen) == 0)) {
        PKM_LogIt("decrypt test case passed\n");
    } else {
        PKM_Error("derypt test case failed\n");
    }

    return crv;
}

CK_RV
PKM_SecretKey(CK_FUNCTION_LIST_PTR pFunctionList,
              CK_SLOT_ID *pSlotList, CK_ULONG slotID,
              CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen)
{
    CK_SESSION_HANDLE hSession;
    CK_RV crv = CKR_OK;
    CK_MECHANISM sAESKeyMech = {
        CKM_AES_KEY_GEN, NULL, 0
    };
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE keyAESType = CKK_AES;
    CK_UTF8CHAR AESlabel[] = "An AES secret key object";
    CK_ULONG AESvalueLen = 16;
    CK_ATTRIBUTE sAESKeyTemplate[9];
    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

    CK_BYTE KEY[16];
    CK_BYTE IV[16];
    static const CK_BYTE CIPHERTEXT[] = {
        0x7e, 0x6a, 0x3f, 0x3b, 0x39, 0x3c, 0xf2, 0x4b,
        0xce, 0xcc, 0x23, 0x6d, 0x80, 0xfd, 0xe0, 0xff
    };
    CK_BYTE ciphertext[64];
    CK_BYTE ciphertext2[64];
    CK_ULONG ciphertextLen, ciphertext2Len, lastLen;
    CK_BYTE plaintext[32];
    CK_BYTE plaintext2[32];
    CK_ULONG plaintextLen, plaintext2Len;
    CK_BYTE wrappedKey[16];
    CK_ULONG wrappedKeyLen;
    CK_MECHANISM aesEcbMech = {
        CKM_AES_ECB, NULL, 0
    };
    CK_OBJECT_HANDLE hTestKey;
    CK_MECHANISM mech_AES_CBC;

    PKM_LogIt("PKM_SecretKey started\n");
    NUMTESTS++; /* increment NUMTESTS */

    memset(ciphertext, 0, sizeof(ciphertext));
    memset(ciphertext2, 0, sizeof(ciphertext2));
    memset(IV, 0x00, sizeof(IV));
    memset(KEY, 0x00, sizeof(KEY));

    mech_AES_CBC.mechanism = CKM_AES_CBC;
    mech_AES_CBC.pParameter = IV;
    mech_AES_CBC.ulParameterLen = sizeof(IV);

    /* AES key template */
    sAESKeyTemplate[0].type = CKA_CLASS;
    sAESKeyTemplate[0].pValue = &class;
    sAESKeyTemplate[0].ulValueLen = sizeof(class);
    sAESKeyTemplate[1].type = CKA_KEY_TYPE;
    sAESKeyTemplate[1].pValue = &keyAESType;
    sAESKeyTemplate[1].ulValueLen = sizeof(keyAESType);
    sAESKeyTemplate[2].type = CKA_LABEL;
    sAESKeyTemplate[2].pValue = AESlabel;
    sAESKeyTemplate[2].ulValueLen = sizeof(AESlabel) - 1;
    sAESKeyTemplate[3].type = CKA_ENCRYPT;
    sAESKeyTemplate[3].pValue = &true;
    sAESKeyTemplate[3].ulValueLen = sizeof(true);
    sAESKeyTemplate[4].type = CKA_DECRYPT;
    sAESKeyTemplate[4].pValue = &true;
    sAESKeyTemplate[4].ulValueLen = sizeof(true);
    sAESKeyTemplate[5].type = CKA_SIGN;
    sAESKeyTemplate[5].pValue = &true;
    sAESKeyTemplate[5].ulValueLen = sizeof(true);
    sAESKeyTemplate[6].type = CKA_VERIFY;
    sAESKeyTemplate[6].pValue = &true;
    sAESKeyTemplate[6].ulValueLen = sizeof(true);
    sAESKeyTemplate[7].type = CKA_UNWRAP;
    sAESKeyTemplate[7].pValue = &true;
    sAESKeyTemplate[7].ulValueLen = sizeof(true);
    sAESKeyTemplate[8].type = CKA_VALUE_LEN;
    sAESKeyTemplate[8].pValue = &AESvalueLen;
    sAESKeyTemplate[8].ulValueLen = sizeof(AESvalueLen);

    crv = pFunctionList->C_OpenSession(pSlotList[slotID], CKF_SERIAL_SESSION,
                                       NULL, NULL, &hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_OpenSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_Login(hSession, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Login with correct password succeeded\n");
    } else {
        PKM_Error("C_Login with correct password failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate an AES key ... \n");
    /* generate an AES Secret Key */
    crv = pFunctionList->C_GenerateKey(hSession, &sAESKeyMech,
                                       sAESKeyTemplate,
                                       NUM_ELEM(sAESKeyTemplate),
                                       &hKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateKey AES succeeded\n");
    } else {
        PKM_Error("C_GenerateKey AES failed with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_EncryptInit(hSession, &aesEcbMech, hKey);
    if (crv != CKR_OK) {
        PKM_Error("C_EncryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    wrappedKeyLen = sizeof(wrappedKey);
    crv = pFunctionList->C_Encrypt(hSession, KEY, sizeof(KEY),
                                   wrappedKey, &wrappedKeyLen);
    if (crv != CKR_OK) {
        PKM_Error("C_Encrypt failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    if (wrappedKeyLen != sizeof(wrappedKey)) {
        PKM_Error("wrappedKeyLen is %lu\n", wrappedKeyLen);
        return crv;
    }
    /* Import an encrypted key */
    crv = pFunctionList->C_UnwrapKey(hSession, &aesEcbMech, hKey,
                                     wrappedKey, wrappedKeyLen,
                                     sAESKeyTemplate,
                                     NUM_ELEM(sAESKeyTemplate),
                                     &hTestKey);
    if (crv != CKR_OK) {
        PKM_Error("C_UnwraPKey failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    /* AES Encrypt the text */
    crv = pFunctionList->C_EncryptInit(hSession, &mech_AES_CBC, hTestKey);
    if (crv != CKR_OK) {
        PKM_Error("C_EncryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    ciphertextLen = sizeof(ciphertext);
    crv = pFunctionList->C_Encrypt(hSession, (CK_BYTE *)PLAINTEXT,
                                   sizeof(PLAINTEXT),
                                   ciphertext, &ciphertextLen);
    if (crv != CKR_OK) {
        PKM_Error("C_Encrypt failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    if ((ciphertextLen == sizeof(CIPHERTEXT)) &&
        (memcmp(ciphertext, CIPHERTEXT, ciphertextLen) == 0)) {
        PKM_LogIt("AES CBCVarKey128 encrypt test case 1 passed\n");
    } else {
        PKM_Error("AES CBCVarKey128 encrypt test case 1 failed\n");
        return crv;
    }

    /* now use EncryptUpdate the text */
    crv = pFunctionList->C_EncryptInit(hSession, &mech_AES_CBC, hTestKey);
    if (crv != CKR_OK) {
        PKM_Error("C_EncryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    ciphertext2Len = sizeof(ciphertext2);
    crv = pFunctionList->C_EncryptUpdate(hSession, (CK_BYTE *)PLAINTEXT,
                                         sizeof(PLAINTEXT),
                                         ciphertext2, &ciphertext2Len);
    if (crv != CKR_OK) {
        PKM_Error("C_EncryptUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    lastLen = sizeof(ciphertext2) - ciphertext2Len;

    crv = pFunctionList->C_EncryptFinal(hSession,
                                        (CK_BYTE *)&ciphertext2[ciphertext2Len],
                                        &lastLen);
    ciphertext2Len = ciphertext2Len + lastLen;

    if ((ciphertextLen == ciphertext2Len) &&
        (memcmp(ciphertext, ciphertext2, sizeof(CIPHERTEXT)) == 0) &&
        (memcmp(ciphertext2, CIPHERTEXT, sizeof(CIPHERTEXT)) == 0)) {
        PKM_LogIt("AES CBCVarKey128 encrypt test case 2 passed\n");
    } else {
        PKM_Error("AES CBCVarKey128 encrypt test case 2 failed\n");
        return CKR_GENERAL_ERROR;
    }

    /* AES CBC Decrypt the text */
    crv = pFunctionList->C_DecryptInit(hSession, &mech_AES_CBC, hTestKey);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    plaintextLen = sizeof(plaintext);
    crv = pFunctionList->C_Decrypt(hSession, ciphertext, ciphertextLen,
                                   plaintext, &plaintextLen);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    if ((plaintextLen == sizeof(PLAINTEXT)) &&
        (memcmp(plaintext, PLAINTEXT, plaintextLen) == 0)) {
        PKM_LogIt("AES CBCVarKey128 decrypt test case 1 passed\n");
    } else {
        PKM_Error("AES CBCVarKey128 derypt test case 1 failed\n");
    }
    /* now use DecryptUpdate the text */
    crv = pFunctionList->C_DecryptInit(hSession, &mech_AES_CBC, hTestKey);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    plaintext2Len = sizeof(plaintext2);
    crv = pFunctionList->C_DecryptUpdate(hSession, ciphertext2,
                                         ciphertext2Len,
                                         plaintext2, &plaintext2Len);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    lastLen = sizeof(plaintext2) - plaintext2Len;
    crv = pFunctionList->C_DecryptFinal(hSession,
                                        (CK_BYTE *)&plaintext2[plaintext2Len],
                                        &lastLen);
    plaintext2Len = plaintext2Len + lastLen;

    if ((plaintextLen == plaintext2Len) &&
        (memcmp(plaintext, plaintext2, plaintext2Len) == 0) &&
        (memcmp(plaintext2, PLAINTEXT, sizeof(PLAINTEXT)) == 0)) {
        PKM_LogIt("AES CBCVarKey128 decrypt test case 2 passed\n");
    } else {
        PKM_Error("AES CBCVarKey128 decrypt test case 2 failed\n");
        return CKR_GENERAL_ERROR;
    }

    crv = pFunctionList->C_Logout(hSession);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Logout succeeded\n");
    } else {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_CloseSession(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    return crv;
}

CK_RV
PKM_PubKeySign(CK_FUNCTION_LIST_PTR pFunctionList,
               CK_SESSION_HANDLE hRwSession,
               CK_OBJECT_HANDLE hPubKey, CK_OBJECT_HANDLE hPrivKey,
               CK_MECHANISM *signMech, const CK_BYTE *pData,
               CK_ULONG pDataLen)
{
    CK_RV crv = CKR_OK;
    CK_BYTE sig[MAX_SIG_SZ];
    CK_ULONG sigLen = 0;

    PKM_LogIt("PKM_PubKeySign started\n");
    NUMTESTS++; /* increment NUMTESTS */
    memset(sig, 0, sizeof(sig));

    /* C_Sign  */
    crv = pFunctionList->C_SignInit(hRwSession, signMech, hPrivKey);
    if (crv != CKR_OK) {
        PKM_Error("C_SignInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    sigLen = sizeof(sig);
    crv = pFunctionList->C_Sign(hRwSession, (CK_BYTE *)pData, pDataLen,
                                sig, &sigLen);
    if (crv != CKR_OK) {
        PKM_Error("C_Sign failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* C_Verify the signature */
    crv = pFunctionList->C_VerifyInit(hRwSession, signMech, hPubKey);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Verify(hRwSession, (CK_BYTE *)pData, pDataLen,
                                  sig, sigLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Verify succeeded\n");
    } else {
        PKM_Error("C_Verify failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* Check that the mechanism is Multi-part */
    if (signMech->mechanism == CKM_DSA ||
        signMech->mechanism == CKM_RSA_PKCS) {
        return crv;
    }

    memset(sig, 0, sizeof(sig));
    /* SignUpdate  */
    crv = pFunctionList->C_SignInit(hRwSession, signMech, hPrivKey);
    if (crv != CKR_OK) {
        PKM_Error("C_SignInit failed with 0x%08lX %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_SignUpdate(hRwSession, (CK_BYTE *)pData, pDataLen);
    if (crv != CKR_OK) {
        PKM_Error("C_Sign failed with 0x%08lX %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    sigLen = sizeof(sig);
    crv = pFunctionList->C_SignFinal(hRwSession, sig, &sigLen);
    if (crv != CKR_OK) {
        PKM_Error("C_Sign failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* C_VerifyUpdate the signature  */
    crv = pFunctionList->C_VerifyInit(hRwSession, signMech,
                                      hPubKey);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyUpdate(hRwSession, (CK_BYTE *)pData,
                                        pDataLen);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyFinal(hRwSession, sig, sigLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_VerifyFinal succeeded\n");
    } else {
        PKM_Error("C_VerifyFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    return crv;
}

CK_RV
PKM_PublicKey(CK_FUNCTION_LIST_PTR pFunctionList,
              CK_SLOT_ID *pSlotList,
              CK_ULONG slotID, CK_UTF8CHAR_PTR pwd,
              CK_ULONG pwdLen)
{
    CK_SESSION_HANDLE hSession;
    CK_RV crv = CKR_OK;

    /*** DSA Key ***/
    CK_MECHANISM dsaParamGenMech;
    CK_ULONG primeBits = DSA_BITS;
    CK_ULONG subPrimeBits = DSA_SUB_PRIME_BITS;
    CK_ULONG seedBits = DSA_SUB_PRIME_BITS;
    CK_ATTRIBUTE dsaParamGenTemplate[3];
    CK_OBJECT_HANDLE hDsaParams = CK_INVALID_HANDLE;
    CK_BYTE DSA_P[DSA_BITS/8];
    CK_BYTE DSA_Q[DSA_SUB_PRIME_BITS/8];
    CK_BYTE DSA_G[DSA_BITS/8];
    CK_MECHANISM dsaKeyPairGenMech;
    CK_ATTRIBUTE dsaPubKeyTemplate[5];
    CK_ATTRIBUTE dsaPrivKeyTemplate[5];
    CK_OBJECT_HANDLE hDSApubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hDSAprivKey = CK_INVALID_HANDLE;

    /* From SHA1ShortMsg.req, Len = 136 */
    CK_BYTE MSG[] = {
        0xba, 0x33, 0x95, 0xfb,
        0x5a, 0xfa, 0x8e, 0x6a,
        0x43, 0xdf, 0x41, 0x6b,
        0x32, 0x7b, 0x74, 0xfa,
        0x44
    };
    CK_BYTE MD[] = {
        0xf7, 0x5d, 0x92, 0xa4,
        0xbb, 0x4d, 0xec, 0xc3,
        0x7c, 0x5c, 0x72, 0xfa,
        0x04, 0x75, 0x71, 0x0a,
        0x06, 0x75, 0x8c, 0x1d
    };

    CK_BYTE sha1Digest[20];
    CK_ULONG sha1DigestLen;
    CK_BYTE dsaSig[DSA_SUB_PRIME_BITS/4];
    CK_ULONG dsaSigLen;
    CK_MECHANISM sha1Mech = {
        CKM_SHA_1, NULL, 0
    };
    CK_MECHANISM dsaMech = {
        CKM_DSA, NULL, 0
    };
    CK_MECHANISM dsaWithSha1Mech = {
        CKM_DSA_SHA1, NULL, 0
    };

    PKM_LogIt("PKM_PublicKey started\n");
    NUMTESTS++; /* increment NUMTESTS */

    /* DSA key init */
    dsaParamGenMech.mechanism = CKM_DSA_PARAMETER_GEN;
    dsaParamGenMech.pParameter = NULL_PTR;
    dsaParamGenMech.ulParameterLen = 0;
    dsaParamGenTemplate[0].type = CKA_PRIME_BITS;
    dsaParamGenTemplate[0].pValue = &primeBits;
    dsaParamGenTemplate[0].ulValueLen = sizeof(primeBits);
    dsaParamGenTemplate[1].type = CKA_SUB_PRIME_BITS;
    dsaParamGenTemplate[1].pValue = &subPrimeBits;
    dsaParamGenTemplate[1].ulValueLen = sizeof(subPrimeBits);
    dsaParamGenTemplate[2].type = CKA_NSS_PQG_SEED_BITS;
    dsaParamGenTemplate[2].pValue = &seedBits;
    dsaParamGenTemplate[2].ulValueLen = sizeof(seedBits);
    dsaPubKeyTemplate[0].type = CKA_PRIME;
    dsaPubKeyTemplate[0].pValue = DSA_P;
    dsaPubKeyTemplate[0].ulValueLen = sizeof(DSA_P);
    dsaPubKeyTemplate[1].type = CKA_SUBPRIME;
    dsaPubKeyTemplate[1].pValue = DSA_Q;
    dsaPubKeyTemplate[1].ulValueLen = sizeof(DSA_Q);
    dsaPubKeyTemplate[2].type = CKA_BASE;
    dsaPubKeyTemplate[2].pValue = DSA_G;
    dsaPubKeyTemplate[2].ulValueLen = sizeof(DSA_G);
    dsaPubKeyTemplate[3].type = CKA_TOKEN;
    dsaPubKeyTemplate[3].pValue = &true;
    dsaPubKeyTemplate[3].ulValueLen = sizeof(true);
    dsaPubKeyTemplate[4].type = CKA_VERIFY;
    dsaPubKeyTemplate[4].pValue = &true;
    dsaPubKeyTemplate[4].ulValueLen = sizeof(true);
    dsaKeyPairGenMech.mechanism = CKM_DSA_KEY_PAIR_GEN;
    dsaKeyPairGenMech.pParameter = NULL_PTR;
    dsaKeyPairGenMech.ulParameterLen = 0;
    dsaPrivKeyTemplate[0].type = CKA_TOKEN;
    dsaPrivKeyTemplate[0].pValue = &true;
    dsaPrivKeyTemplate[0].ulValueLen = sizeof(true);
    dsaPrivKeyTemplate[1].type = CKA_PRIVATE;
    dsaPrivKeyTemplate[1].pValue = &true;
    dsaPrivKeyTemplate[1].ulValueLen = sizeof(true);
    dsaPrivKeyTemplate[2].type = CKA_SENSITIVE;
    dsaPrivKeyTemplate[2].pValue = &true;
    dsaPrivKeyTemplate[2].ulValueLen = sizeof(true);
    dsaPrivKeyTemplate[3].type = CKA_SIGN,
    dsaPrivKeyTemplate[3].pValue = &true;
    dsaPrivKeyTemplate[3].ulValueLen = sizeof(true);
    dsaPrivKeyTemplate[4].type = CKA_EXTRACTABLE;
    dsaPrivKeyTemplate[4].pValue = &true;
    dsaPrivKeyTemplate[4].ulValueLen = sizeof(true);

    crv = pFunctionList->C_OpenSession(pSlotList[slotID],
                                       CKF_RW_SESSION | CKF_SERIAL_SESSION,
                                       NULL, NULL, &hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_OpenSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_Login(hSession, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Login with correct password succeeded\n");
    } else {
        PKM_Error("C_Login with correct password failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate DSA PQG domain parameters ... \n");
    /* Generate DSA domain parameters PQG */
    crv = pFunctionList->C_GenerateKey(hSession, &dsaParamGenMech,
                                       dsaParamGenTemplate,
                                       NUM_ELEM(dsaParamGenTemplate),
                                       &hDsaParams);
    if (crv == CKR_OK) {
        PKM_LogIt("DSA domain parameter generation succeeded\n");
    } else {
        PKM_Error("DSA domain parameter generation failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_GetAttributeValue(hSession, hDsaParams,
                                             dsaPubKeyTemplate, 3);
    if (crv == CKR_OK) {
        PKM_LogIt("Getting DSA domain parameters succeeded\n");
    } else {
        PKM_Error("Getting DSA domain parameters failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_DestroyObject(hSession, hDsaParams);
    if (crv == CKR_OK) {
        PKM_LogIt("Destroying DSA domain parameters succeeded\n");
    } else {
        PKM_Error("Destroying DSA domain parameters failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate a DSA key pair ... \n");
    /* Generate a persistent DSA key pair */
    crv = pFunctionList->C_GenerateKeyPair(hSession, &dsaKeyPairGenMech,
                                           dsaPubKeyTemplate,
                                           NUM_ELEM(dsaPubKeyTemplate),
                                           dsaPrivKeyTemplate,
                                           NUM_ELEM(dsaPrivKeyTemplate),
                                           &hDSApubKey, &hDSAprivKey);
    if (crv == CKR_OK) {
        PKM_LogIt("DSA key pair generation succeeded\n");
    } else {
        PKM_Error("DSA key pair generation failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* Compute SHA-1 digest */
    crv = pFunctionList->C_DigestInit(hSession, &sha1Mech);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    sha1DigestLen = sizeof(sha1Digest);
    crv = pFunctionList->C_Digest(hSession, MSG, sizeof(MSG),
                                  sha1Digest, &sha1DigestLen);
    if (crv != CKR_OK) {
        PKM_Error("C_Digest failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    if (sha1DigestLen != sizeof(sha1Digest)) {
        PKM_Error("sha1DigestLen is %lu\n", sha1DigestLen);
        return crv;
    }

    if (memcmp(sha1Digest, MD, sizeof(MD)) == 0) {
        PKM_LogIt("SHA-1 SHA1ShortMsg test case Len = 136 passed\n");
    } else {
        PKM_Error("SHA-1 SHA1ShortMsg test case Len = 136 failed\n");
    }

    crv = PKM_PubKeySign(pFunctionList, hSession,
                         hDSApubKey, hDSAprivKey,
                         &dsaMech, sha1Digest, sizeof(sha1Digest));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_PubKeySign CKM_DSA succeeded \n");
    } else {
        PKM_Error("PKM_PubKeySign failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = PKM_PubKeySign(pFunctionList, hSession,
                         hDSApubKey, hDSAprivKey,
                         &dsaWithSha1Mech, PLAINTEXT, sizeof(PLAINTEXT));
    if (crv == CKR_OK) {
        PKM_LogIt("PKM_PubKeySign CKM_DSA_SHA1 succeeded \n");
    } else {
        PKM_Error("PKM_PubKeySign failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* Sign with DSA */
    crv = pFunctionList->C_SignInit(hSession, &dsaMech, hDSAprivKey);
    if (crv != CKR_OK) {
        PKM_Error("C_SignInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    dsaSigLen = sizeof(dsaSig);
    crv = pFunctionList->C_Sign(hSession, sha1Digest, sha1DigestLen,
                                dsaSig, &dsaSigLen);
    if (crv != CKR_OK) {
        PKM_Error("C_Sign failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* Verify the DSA signature */
    crv = pFunctionList->C_VerifyInit(hSession, &dsaMech, hDSApubKey);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Verify(hSession, sha1Digest, sha1DigestLen,
                                  dsaSig, dsaSigLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Verify succeeded\n");
    } else {
        PKM_Error("C_Verify failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* Verify the signature in a different way */
    crv = pFunctionList->C_VerifyInit(hSession, &dsaWithSha1Mech,
                                      hDSApubKey);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyUpdate(hSession, MSG, 1);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyUpdate(hSession, MSG + 1, sizeof(MSG) - 1);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyFinal(hSession, dsaSig, dsaSigLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_VerifyFinal succeeded\n");
    } else {
        PKM_Error("C_VerifyFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* Verify the signature in a different way */
    crv = pFunctionList->C_VerifyInit(hSession, &dsaWithSha1Mech,
                                      hDSApubKey);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyInit failed with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyUpdate(hSession, MSG, 1);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyUpdate failed with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyUpdate(hSession, MSG + 1, sizeof(MSG) - 1);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyUpdate failed with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyFinal(hSession, dsaSig, dsaSigLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_VerifyFinal of multi update succeeded.\n");
    } else {
        PKM_Error("C_VerifyFinal of multi update failed with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    /* Now modify the data */
    MSG[0] += 1;
    /* Compute SHA-1 digest */
    crv = pFunctionList->C_DigestInit(hSession, &sha1Mech);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    sha1DigestLen = sizeof(sha1Digest);
    crv = pFunctionList->C_Digest(hSession, MSG, sizeof(MSG),
                                  sha1Digest, &sha1DigestLen);
    if (crv != CKR_OK) {
        PKM_Error("C_Digest failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyInit(hSession, &dsaMech, hDSApubKey);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Verify(hSession, sha1Digest, sha1DigestLen,
                                  dsaSig, dsaSigLen);
    if (crv != CKR_SIGNATURE_INVALID) {
        PKM_Error("C_Verify of modified data succeeded\n");
        return crv;
    } else {
        PKM_LogIt("C_Verify of modified data returned as EXPECTED "
                  " with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
    }

    crv = pFunctionList->C_Logout(hSession);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Logout succeeded\n");
    } else {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_CloseSession(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    return crv;
}

CK_RV
PKM_Hmac(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession,
         CK_OBJECT_HANDLE sKey, CK_MECHANISM *hmacMech,
         const CK_BYTE *pData, CK_ULONG pDataLen)
{

    CK_RV crv = CKR_OK;

    CK_BYTE hmac1[HMAC_MAX_LENGTH];
    CK_ULONG hmac1Len = 0;
    CK_BYTE hmac2[HMAC_MAX_LENGTH];
    CK_ULONG hmac2Len = 0;

    memset(hmac1, 0, sizeof(hmac1));
    memset(hmac2, 0, sizeof(hmac2));

    PKM_LogIt("PKM_Hmac started\n");
    NUMTESTS++; /* increment NUMTESTS */

    crv = pFunctionList->C_SignInit(hSession, hmacMech, sKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_SignInit succeeded\n");
    } else {
        PKM_Error("C_SignInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    hmac1Len = sizeof(hmac1);
    crv = pFunctionList->C_Sign(hSession, (CK_BYTE *)pData,
                                pDataLen,
                                (CK_BYTE *)hmac1, &hmac1Len);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Sign succeeded\n");
    } else {
        PKM_Error("C_Sign failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_SignInit(hSession, hmacMech, sKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_SignInit succeeded\n");
    } else {
        PKM_Error("C_SignInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_SignUpdate(hSession, (CK_BYTE *)pData,
                                      pDataLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_SignUpdate succeeded\n");
    } else {
        PKM_Error("C_SignUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    hmac2Len = sizeof(hmac2);
    crv = pFunctionList->C_SignFinal(hSession, (CK_BYTE *)hmac2, &hmac2Len);
    if (crv == CKR_OK) {
        PKM_LogIt("C_SignFinal succeeded\n");
    } else {
        PKM_Error("C_SignFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    if ((hmac1Len == hmac2Len) && (memcmp(hmac1, hmac2, hmac1Len) == 0)) {
        PKM_LogIt("hmacs are equal!\n");
    } else {
        PKM_Error("hmacs are not equal!\n");
    }
    crv = pFunctionList->C_VerifyInit(hSession, hmacMech, sKey);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Verify(hSession, (CK_BYTE *)pData,
                                  pDataLen,
                                  (CK_BYTE *)hmac2, hmac2Len);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Verify of hmac succeeded\n");
    } else {
        PKM_Error("C_Verify failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyInit(hSession, hmacMech, sKey);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyUpdate(hSession, (CK_BYTE *)pData,
                                        pDataLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_VerifyUpdate of hmac succeeded\n");
    } else {
        PKM_Error("C_VerifyUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyFinal(hSession, (CK_BYTE *)hmac1,
                                       hmac1Len);
    if (crv == CKR_OK) {
        PKM_LogIt("C_VerifyFinal of hmac succeeded\n");
    } else {
        PKM_Error("C_VerifyFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    return crv;
}

CK_RV
PKM_FindAllObjects(CK_FUNCTION_LIST_PTR pFunctionList,
                   CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                   CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen)
{
    CK_RV crv = CKR_OK;

    CK_SESSION_HANDLE h = (CK_SESSION_HANDLE)0;
    CK_SESSION_INFO sinfo;
    CK_ATTRIBUTE_PTR pTemplate;
    CK_ULONG tnObjects = 0;
    int curMode;
    unsigned int i;
    unsigned int number_of_all_known_attribute_types = totalKnownType(ConstAttribute);

    PKM_LogIt("PKM_FindAllObjects started\n");
    NUMTESTS++; /* increment NUMTESTS */

    crv = pFunctionList->C_OpenSession(pSlotList[slotID], CKF_SERIAL_SESSION,
                                       NULL, NULL, &h);
    if (CKR_OK != crv) {
        PKM_Error("C_OpenSession(%lu, CKF_SERIAL_SESSION, , )"
                  "returned 0x%08X, %-26s\n",
                  pSlotList[slotID], crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("    Opened a session: handle = 0x%08x\n", h);

    (void)memset(&sinfo, 0, sizeof(CK_SESSION_INFO));
    crv = pFunctionList->C_GetSessionInfo(h, &sinfo);
    if (CKR_OK != crv) {
        PKM_LogIt("C_GetSessionInfo(%lu, ) returned 0x%08X, %-26s\n", h, crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("    SESSION INFO:\n");
    PKM_LogIt("        slotID = %lu\n", sinfo.slotID);
    PKM_LogIt("        state = %lu\n", sinfo.state);
    PKM_LogIt("        flags = 0x%08x\n", sinfo.flags);
#ifdef CKF_EXCLUSIVE_SESSION
    PKM_LogIt("            -> EXCLUSIVE SESSION = %s\n", sinfo.flags &
                                                                 CKF_EXCLUSIVE_SESSION
                                                             ? "TRUE"
                                                             : "FALSE");
#endif /* CKF_EXCLUSIVE_SESSION */
    PKM_LogIt("            -> RW SESSION = %s\n", sinfo.flags &
                                                          CKF_RW_SESSION
                                                      ? "TRUE"
                                                      : "FALSE");
    PKM_LogIt("            -> SERIAL SESSION = %s\n", sinfo.flags &
                                                              CKF_SERIAL_SESSION
                                                          ? "TRUE"
                                                          : "FALSE");
#ifdef CKF_INSERTION_CALLBACK
    PKM_LogIt("            -> INSERTION CALLBACK = %s\n", sinfo.flags &
                                                                  CKF_INSERTION_CALLBACK
                                                              ? "TRUE"
                                                              : "FALSE");
#endif /* CKF_INSERTION_CALLBACK */
    PKM_LogIt("        ulDeviceError = %lu\n", sinfo.ulDeviceError);
    PKM_LogIt("\n");

    crv = pFunctionList->C_FindObjectsInit(h, NULL, 0);
    if (CKR_OK != crv) {
        PKM_LogIt("C_FindObjectsInit(%lu, NULL, 0) returned "
                  "0x%08X, %-26s\n",
                  h, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    pTemplate = (CK_ATTRIBUTE_PTR)calloc(number_of_all_known_attribute_types,
                                         sizeof(CK_ATTRIBUTE));
    if ((CK_ATTRIBUTE_PTR)NULL == pTemplate) {
        PKM_Error("[pTemplate memory allocation of %lu bytes failed]\n",
                  number_of_all_known_attribute_types *
                      sizeof(CK_ATTRIBUTE));
        return crv;
    }

    PKM_LogIt("    All objects:\n");
    /* Printing table set to NOMODE */
    curMode = MODE;
    MODE = NOMODE;

    while (1) {
        CK_OBJECT_HANDLE o = (CK_OBJECT_HANDLE)0;
        CK_ULONG nObjects = 0;
        CK_ULONG k;
        CK_ULONG nAttributes = 0;
        CK_ATTRIBUTE_PTR pT2;
        CK_ULONG l;
        const char *attName = NULL;

        crv = pFunctionList->C_FindObjects(h, &o, 1, &nObjects);
        if (CKR_OK != crv) {
            PKM_Error("C_FindObjects(%lu, , 1, ) returned 0x%08X, %-26s\n",
                      h, crv, PKM_CK_RVtoStr(crv));
            return crv;
        }

        if (0 == nObjects) {
            PKM_LogIt("\n");
            break;
        }

        tnObjects++;

        PKM_LogIt("        OBJECT HANDLE %lu:\n", o);

        k = 0;
        for (i = 0; i < constCount; i++) {
            if (consts[i].type == ConstAttribute) {
                pTemplate[k].type = consts[i].value;
                pTemplate[k].pValue = (CK_VOID_PTR)NULL;
                pTemplate[k].ulValueLen = 0;
                k++;
            }
            assert(k <= number_of_all_known_attribute_types);
        }

        crv = pFunctionList->C_GetAttributeValue(h, o, pTemplate,
                                                 number_of_all_known_attribute_types);
        switch (crv) {
            case CKR_OK:
            case CKR_ATTRIBUTE_SENSITIVE:
            case CKR_ATTRIBUTE_TYPE_INVALID:
            case CKR_BUFFER_TOO_SMALL:
                break;
            default:
                PKM_Error("C_GetAtributeValue(%lu, %lu, {all attribute types},"
                          "%lu) returned 0x%08X, %-26s\n",
                          h, o, number_of_all_known_attribute_types, crv,
                          PKM_CK_RVtoStr(crv));
                return crv;
        }

        for (k = 0; k < (CK_ULONG)number_of_all_known_attribute_types; k++) {
            if (-1 != (CK_LONG)pTemplate[k].ulValueLen) {
                nAttributes++;
            }
        }

        PKM_LogIt("            %lu attributes:\n", nAttributes);
        for (k = 0; k < (CK_ULONG)number_of_all_known_attribute_types;
             k++) {
            if (-1 != (CK_LONG)pTemplate[k].ulValueLen) {
                attName = getNameFromAttribute(pTemplate[k].type);
                if (!attName) {
                    PKM_Error("Unable to find attribute name update pk11table.c\n");
                }
                PKM_LogIt("                %s 0x%08x (len = %lu)\n",
                          attName,
                          pTemplate[k].type,
                          pTemplate[k].ulValueLen);
            }
        }
        PKM_LogIt("\n");

        pT2 = (CK_ATTRIBUTE_PTR)calloc(nAttributes, sizeof(CK_ATTRIBUTE));
        if ((CK_ATTRIBUTE_PTR)NULL == pT2) {
            PKM_Error("[pT2 memory allocation of %lu bytes failed]\n",
                      nAttributes * sizeof(CK_ATTRIBUTE));
            return crv;
        }

        /* allocate memory for the attribute values */
        for (l = 0, k = 0; k < (CK_ULONG)number_of_all_known_attribute_types;
             k++) {
            if (-1 != (CK_LONG)pTemplate[k].ulValueLen) {
                pT2[l].type = pTemplate[k].type;
                pT2[l].ulValueLen = pTemplate[k].ulValueLen;
                if (pT2[l].ulValueLen > 0) {
                    pT2[l].pValue = (CK_VOID_PTR)malloc(pT2[l].ulValueLen);
                    if ((CK_VOID_PTR)NULL == pT2[l].pValue) {
                        PKM_Error("pValue memory allocation of %lu bytes failed]\n",
                                  pT2[l].ulValueLen);
                        return crv;
                    }
                } else
                    pT2[l].pValue = (CK_VOID_PTR)NULL;
                l++;
            }
        }

        assert(l == nAttributes);

        crv = pFunctionList->C_GetAttributeValue(h, o, pT2, nAttributes);
        switch (crv) {
            case CKR_OK:
            case CKR_ATTRIBUTE_SENSITIVE:
            case CKR_ATTRIBUTE_TYPE_INVALID:
            case CKR_BUFFER_TOO_SMALL:
                break;
            default:
                PKM_Error("C_GetAtributeValue(%lu, %lu, {existent attribute"
                          " types}, %lu) returned 0x%08X, %-26s\n",
                          h, o, nAttributes, crv, PKM_CK_RVtoStr(crv));
                return crv;
        }

        for (l = 0; l < nAttributes; l++) {
            attName = getNameFromAttribute(pT2[l].type);
            if (!attName)
                attName = "unknown attribute";
            PKM_LogIt("            type = %s len = %ld",
                      attName, (CK_LONG)pT2[l].ulValueLen);

            if (-1 == (CK_LONG)pT2[l].ulValueLen) {
                ;
            } else {
                CK_ULONG m;

                if (pT2[l].ulValueLen <= 8) {
                    PKM_LogIt(", value = ");
                } else {
                    PKM_LogIt(", value = \n                ");
                }

                for (m = 0; (m < pT2[l].ulValueLen) && (m < 20); m++) {
                    PKM_LogIt("%02x", (CK_ULONG)(0xff &
                                                 ((CK_CHAR_PTR)pT2[l].pValue)[m]));
                }

                PKM_LogIt(" ");

                for (m = 0; (m < pT2[l].ulValueLen) && (m < 20); m++) {
                    CK_CHAR c = ((CK_CHAR_PTR)pT2[l].pValue)[m];
                    if ((c < 0x20) || (c >= 0x7f)) {
                        c = '.';
                    }
                    PKM_LogIt("%c", c);
                }
            }

            PKM_LogIt("\n");
        }

        PKM_LogIt("\n");

        for (l = 0; l < nAttributes; l++) {
            if (pT2[l].pValue) {
                free(pT2[l].pValue);
            }
        }
        free(pT2);
    } /* while(1) */

    MODE = curMode; /* reset the logging MODE */

    crv = pFunctionList->C_FindObjectsFinal(h);
    if (CKR_OK != crv) {
        PKM_Error("C_FindObjectsFinal(%lu) returned 0x%08X, %-26s\n", h, crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("    (%lu objects total)\n", tnObjects);

    crv = pFunctionList->C_CloseSession(h);
    if (CKR_OK != crv) {
        PKM_Error("C_CloseSession(%lu) returned 0x%08X, %-26s\n", h, crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    return crv;
}
/* session to create, find, and delete a couple session objects */
CK_RV
PKM_MultiObjectManagement(CK_FUNCTION_LIST_PTR pFunctionList,
                          CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                          CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen)
{

    CK_RV crv = CKR_OK;

    CK_SESSION_HANDLE h = (CK_SESSION_HANDLE)0;
    CK_SESSION_HANDLE h2 = (CK_SESSION_HANDLE)0;
    CK_ATTRIBUTE one[7], two[7], three[7], delta[1], mask[1];
    CK_OBJECT_CLASS cko_data = CKO_DATA;
    char *key = "TEST PROGRAM";
    CK_ULONG key_len = 0;
    CK_OBJECT_HANDLE hOneIn = (CK_OBJECT_HANDLE)0;
    CK_OBJECT_HANDLE hTwoIn = (CK_OBJECT_HANDLE)0;
    CK_OBJECT_HANDLE hThreeIn = (CK_OBJECT_HANDLE)0;
    CK_OBJECT_HANDLE hDeltaIn = (CK_OBJECT_HANDLE)0;
    CK_OBJECT_HANDLE found[10];
    CK_ULONG nFound;
    CK_ULONG hDeltaLen, hThreeLen = 0;

    CK_TOKEN_INFO tinfo;

    PKM_LogIt("PKM_MultiObjectManagement started\n");
    NUMTESTS++; /* increment NUMTESTS */
    key_len = sizeof(key);
    crv = pFunctionList->C_OpenSession(pSlotList[slotID],
                                       CKF_SERIAL_SESSION, NULL, NULL, &h);
    if (CKR_OK != crv) {
        PKM_Error("C_OpenSession(%lu, CKF_SERIAL_SESSION, , )"
                  "returned 0x%08X, %-26s\n",
                  pSlotList[slotID], crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Login(h, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Login with correct password succeeded\n");
    } else {
        PKM_Error("C_Login with correct password failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    (void)memset(&tinfo, 0, sizeof(CK_TOKEN_INFO));
    crv = pFunctionList->C_GetTokenInfo(pSlotList[slotID], &tinfo);
    if (CKR_OK != crv) {
        PKM_Error("C_GetTokenInfo(%lu, ) returned 0x%08X, %-26s\n",
                  pSlotList[slotID], crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("    Opened a session: handle = 0x%08x\n", h);

    one[0].type = CKA_CLASS;
    one[0].pValue = &cko_data;
    one[0].ulValueLen = sizeof(CK_OBJECT_CLASS);
    one[1].type = CKA_TOKEN;
    one[1].pValue = &false;
    one[1].ulValueLen = sizeof(CK_BBOOL);
    one[2].type = CKA_PRIVATE;
    one[2].pValue = &false;
    one[2].ulValueLen = sizeof(CK_BBOOL);
    one[3].type = CKA_MODIFIABLE;
    one[3].pValue = &true;
    one[3].ulValueLen = sizeof(CK_BBOOL);
    one[4].type = CKA_LABEL;
    one[4].pValue = "Test data object one";
    one[4].ulValueLen = strlen(one[4].pValue);
    one[5].type = CKA_APPLICATION;
    one[5].pValue = key;
    one[5].ulValueLen = key_len;
    one[6].type = CKA_VALUE;
    one[6].pValue = "Object one";
    one[6].ulValueLen = strlen(one[6].pValue);

    two[0].type = CKA_CLASS;
    two[0].pValue = &cko_data;
    two[0].ulValueLen = sizeof(CK_OBJECT_CLASS);
    two[1].type = CKA_TOKEN;
    two[1].pValue = &false;
    two[1].ulValueLen = sizeof(CK_BBOOL);
    two[2].type = CKA_PRIVATE;
    two[2].pValue = &false;
    two[2].ulValueLen = sizeof(CK_BBOOL);
    two[3].type = CKA_MODIFIABLE;
    two[3].pValue = &true;
    two[3].ulValueLen = sizeof(CK_BBOOL);
    two[4].type = CKA_LABEL;
    two[4].pValue = "Test data object two";
    two[4].ulValueLen = strlen(two[4].pValue);
    two[5].type = CKA_APPLICATION;
    two[5].pValue = key;
    two[5].ulValueLen = key_len;
    two[6].type = CKA_VALUE;
    two[6].pValue = "Object two";
    two[6].ulValueLen = strlen(two[6].pValue);

    three[0].type = CKA_CLASS;
    three[0].pValue = &cko_data;
    three[0].ulValueLen = sizeof(CK_OBJECT_CLASS);
    three[1].type = CKA_TOKEN;
    three[1].pValue = &false;
    three[1].ulValueLen = sizeof(CK_BBOOL);
    three[2].type = CKA_PRIVATE;
    three[2].pValue = &false;
    three[2].ulValueLen = sizeof(CK_BBOOL);
    three[3].type = CKA_MODIFIABLE;
    three[3].pValue = &true;
    three[3].ulValueLen = sizeof(CK_BBOOL);
    three[4].type = CKA_LABEL;
    three[4].pValue = "Test data object three";
    three[4].ulValueLen = strlen(three[4].pValue);
    three[5].type = CKA_APPLICATION;
    three[5].pValue = key;
    three[5].ulValueLen = key_len;
    three[6].type = CKA_VALUE;
    three[6].pValue = "Object three";
    three[6].ulValueLen = strlen(three[6].pValue);

    crv = pFunctionList->C_CreateObject(h, one, 7, &hOneIn);
    if (CKR_OK != crv) {
        PKM_Error("C_CreateObject(%lu, one, 7, ) returned 0x%08X, %-26s\n",
                  h, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("    Created object one: handle = %lu\n", hOneIn);

    crv = pFunctionList->C_CreateObject(h, two, 7, &hTwoIn);
    if (CKR_OK != crv) {
        PKM_Error("C_CreateObject(%lu, two, 7, ) returned 0x%08X, %-26s\n",
                  h, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("    Created object two: handle = %lu\n", hTwoIn);

    crv = pFunctionList->C_CreateObject(h, three, 7, &hThreeIn);
    if (CKR_OK != crv) {
        PKM_Error("C_CreateObject(%lu, three, 7, ) returned 0x%08x\n",
                  h, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_GetObjectSize(h, hThreeIn, &hThreeLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GetObjectSize succeeded\n");
    } else {
        PKM_Error("C_GetObjectSize failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("    Created object three: handle = %lu\n", hThreeIn);

    delta[0].type = CKA_VALUE;
    delta[0].pValue = "Copied object";
    delta[0].ulValueLen = strlen(delta[0].pValue);

    crv = pFunctionList->C_CopyObject(h, hThreeIn, delta, 1, &hDeltaIn);
    if (CKR_OK != crv) {
        PKM_Error("C_CopyObject(%lu, %lu, delta, 1, ) returned "
                  "0x%08X, %-26s\n",
                  h, hThreeIn, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_GetObjectSize(h, hDeltaIn, &hDeltaLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GetObjectSize succeeded\n");
    } else {
        PKM_Error("C_GetObjectSize failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    if (hThreeLen == hDeltaLen) {
        PKM_LogIt("Copied object size same as orginal\n");
    } else {
        PKM_Error("Copied object different from original\n");
        return CKR_DEVICE_ERROR;
    }

    PKM_LogIt("    Copied object three: new handle = %lu\n", hDeltaIn);

    mask[0].type = CKA_APPLICATION;
    mask[0].pValue = key;
    mask[0].ulValueLen = key_len;

    crv = pFunctionList->C_FindObjectsInit(h, mask, 1);
    if (CKR_OK != crv) {
        PKM_Error("C_FindObjectsInit(%lu, mask, 1) returned 0x%08X, %-26s\n",
                  h, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    (void)memset(&found, 0, sizeof(found));
    nFound = 0;
    crv = pFunctionList->C_FindObjects(h, found, 10, &nFound);
    if (CKR_OK != crv) {
        PKM_Error("C_FindObjects(%lu,, 10, ) returned 0x%08X, %-26s\n",
                  h, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    if (4 != nFound) {
        PKM_Error("Found %lu objects, not 4.\n", nFound);
        return crv;
    }

    PKM_LogIt("    Found 4 objects: %lu, %lu, %lu, %lu\n",
              found[0], found[1], found[2], found[3]);

    crv = pFunctionList->C_FindObjectsFinal(h);
    if (CKR_OK != crv) {
        PKM_Error("C_FindObjectsFinal(%lu) returned 0x%08X, %-26s\n",
                  h, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_DestroyObject(h, hThreeIn);
    if (CKR_OK != crv) {
        PKM_Error("C_DestroyObject(%lu, %lu) returned 0x%08X, %-26s\n", h,
                  hThreeIn, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("    Destroyed object three (handle = %lu)\n", hThreeIn);

    delta[0].type = CKA_APPLICATION;
    delta[0].pValue = "Changed application";
    delta[0].ulValueLen = strlen(delta[0].pValue);

    crv = pFunctionList->C_SetAttributeValue(h, hTwoIn, delta, 1);
    if (CKR_OK != crv) {
        PKM_Error("C_SetAttributeValue(%lu, %lu, delta, 1) returned "
                  "0x%08X, %-26s\n",
                  h, hTwoIn, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("    Changed object two (handle = %lu).\n", hTwoIn);

    /* Can another session find these session objects? */

    crv = pFunctionList->C_OpenSession(pSlotList[slotID], CKF_SERIAL_SESSION,
                                       NULL, NULL, &h2);
    if (CKR_OK != crv) {
        PKM_Error("C_OpenSession(%lu, CKF_SERIAL_SESSION, , )"
                  " returned 0x%08X, %-26s\n",
                  pSlotList[slotID], crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    PKM_LogIt("    Opened a second session: handle = 0x%08x\n", h2);

    /* mask is still the same */

    crv = pFunctionList->C_FindObjectsInit(h2, mask, 1);
    if (CKR_OK != crv) {
        PKM_Error("C_FindObjectsInit(%lu, mask, 1) returned 0x%08X, %-26s\n",
                  h2, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    (void)memset(&found, 0, sizeof(found));
    nFound = 0;
    crv = pFunctionList->C_FindObjects(h2, found, 10, &nFound);
    if (CKR_OK != crv) {
        PKM_Error("C_FindObjects(%lu,, 10, ) returned 0x%08X, %-26s\n",
                  h2, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    if (2 != nFound) {
        PKM_Error("Found %lu objects, not 2.\n", nFound);
        return crv;
    }

    PKM_LogIt("    Found 2 objects: %lu, %lu\n",
              found[0], found[1]);

    crv = pFunctionList->C_FindObjectsFinal(h2);
    if (CKR_OK != crv) {
        PKM_Error("C_FindObjectsFinal(%lu) returned 0x%08X, %-26s\n", h2, crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Logout(h);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Logout succeeded\n");
    } else {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_CloseAllSessions(pSlotList[slotID]);
    if (CKR_OK != crv) {
        PKM_Error("C_CloseAllSessions(%lu) returned 0x%08X, %-26s\n",
                  pSlotList[slotID], crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("\n");
    return crv;
}

CK_RV
PKM_OperationalState(CK_FUNCTION_LIST_PTR pFunctionList,
                     CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                     CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen)
{
    CK_SESSION_HANDLE hSession;
    CK_RV crv = CKR_OK;
    CK_MECHANISM sAESKeyMech = {
        CKM_AES_KEY_GEN, NULL, 0
    };
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE keyAESType = CKK_AES;
    CK_UTF8CHAR AESlabel[] = "An AES secret key object";
    CK_ULONG AESvalueLen = 16;
    CK_ATTRIBUTE sAESKeyTemplate[9];
    CK_OBJECT_HANDLE sKey = CK_INVALID_HANDLE;
    CK_BYTE_PTR pstate = NULL;
    CK_ULONG statelen, digestlen, plainlen, plainlen_1, plainlen_2, slen;

    static const CK_UTF8CHAR *plaintext = (CK_UTF8CHAR *)"Firefox rules.";
    static const CK_UTF8CHAR *plaintext_1 = (CK_UTF8CHAR *)"Thunderbird rules.";
    static const CK_UTF8CHAR *plaintext_2 = (CK_UTF8CHAR *)"Firefox and Thunderbird.";

    char digest[MAX_DIGEST_SZ], digest_1[MAX_DIGEST_SZ];
    char sign[MAX_SIG_SZ];
    CK_MECHANISM signmech;
    CK_MECHANISM digestmech;

    PKM_LogIt("PKM_OperationalState started\n");
    NUMTESTS++; /* increment NUMTESTS */

    /* AES key template */
    sAESKeyTemplate[0].type = CKA_CLASS;
    sAESKeyTemplate[0].pValue = &class;
    sAESKeyTemplate[0].ulValueLen = sizeof(class);
    sAESKeyTemplate[1].type = CKA_KEY_TYPE;
    sAESKeyTemplate[1].pValue = &keyAESType;
    sAESKeyTemplate[1].ulValueLen = sizeof(keyAESType);
    sAESKeyTemplate[2].type = CKA_LABEL;
    sAESKeyTemplate[2].pValue = AESlabel;
    sAESKeyTemplate[2].ulValueLen = sizeof(AESlabel) - 1;
    sAESKeyTemplate[3].type = CKA_ENCRYPT;
    sAESKeyTemplate[3].pValue = &true;
    sAESKeyTemplate[3].ulValueLen = sizeof(true);
    sAESKeyTemplate[4].type = CKA_DECRYPT;
    sAESKeyTemplate[4].pValue = &true;
    sAESKeyTemplate[4].ulValueLen = sizeof(true);
    sAESKeyTemplate[5].type = CKA_SIGN;
    sAESKeyTemplate[5].pValue = &true;
    sAESKeyTemplate[5].ulValueLen = sizeof(true);
    sAESKeyTemplate[6].type = CKA_VERIFY;
    sAESKeyTemplate[6].pValue = &true;
    sAESKeyTemplate[6].ulValueLen = sizeof(true);
    sAESKeyTemplate[7].type = CKA_UNWRAP;
    sAESKeyTemplate[7].pValue = &true;
    sAESKeyTemplate[7].ulValueLen = sizeof(true);
    sAESKeyTemplate[8].type = CKA_VALUE_LEN;
    sAESKeyTemplate[8].pValue = &AESvalueLen;
    sAESKeyTemplate[8].ulValueLen = sizeof(AESvalueLen);

    signmech.mechanism = CKM_SHA_1_HMAC;
    signmech.pParameter = NULL;
    signmech.ulParameterLen = 0;
    digestmech.mechanism = CKM_SHA256;
    digestmech.pParameter = NULL;
    digestmech.ulParameterLen = 0;

    plainlen = strlen((char *)plaintext);
    plainlen_1 = strlen((char *)plaintext_1);
    plainlen_2 = strlen((char *)plaintext_2);
    digestlen = MAX_DIGEST_SZ;

    crv = pFunctionList->C_OpenSession(pSlotList[slotID], CKF_SERIAL_SESSION,
                                       NULL, NULL, &hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_OpenSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_Login(hSession, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Login with correct password succeeded\n");
    } else {
        PKM_Error("C_Login with correct password failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    PKM_LogIt("Generate an AES key ...\n");
    /* generate an AES Secret Key */
    crv = pFunctionList->C_GenerateKey(hSession, &sAESKeyMech,
                                       sAESKeyTemplate,
                                       NUM_ELEM(sAESKeyTemplate),
                                       &sKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateKey AES succeeded\n");
    } else {
        PKM_Error("C_GenerateKey AES failed with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_SignInit(hSession, &signmech, sKey);
    if (crv != CKR_OK) {
        PKM_Error("C_SignInit failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    slen = sizeof(sign);
    crv = pFunctionList->C_Sign(hSession, (CK_BYTE_PTR)plaintext, plainlen,
                                (CK_BYTE_PTR)sign, &slen);
    if (crv != CKR_OK) {
        PKM_Error("C_Sign failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_DestroyObject(hSession, sKey);
    if (crv != CKR_OK) {
        PKM_Error("C_DestroyObject failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    digestlen = MAX_DIGEST_SZ;
    crv = pFunctionList->C_DigestInit(hSession, &digestmech);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestInit failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_DigestUpdate(hSession, (CK_BYTE_PTR)plaintext,
                                        plainlen);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestUpdate failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_GetOperationState(hSession, NULL, &statelen);
    if (crv != CKR_OK) {
        PKM_Error("C_GetOperationState failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    pstate = (CK_BYTE_PTR)malloc(statelen * sizeof(CK_BYTE_PTR));
    crv = pFunctionList->C_GetOperationState(hSession, pstate, &statelen);
    if (crv != CKR_OK) {
        PKM_Error("C_GetOperationState failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_DigestUpdate(hSession, (CK_BYTE_PTR)plaintext_1,
                                        plainlen_1);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestUpdate failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_DigestUpdate(hSession, (CK_BYTE_PTR)plaintext_2,
                                        plainlen_2);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestUpdate failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /*
     *      This will override/negate the above 2 digest_update
     *      operations
     */
    crv = pFunctionList->C_SetOperationState(hSession, pstate, statelen,
                                             0, 0);
    if (crv != CKR_OK) {
        PKM_Error("C_SetOperationState failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_DigestFinal(hSession, (CK_BYTE_PTR)digest,
                                       &digestlen);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestFinal failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    digestlen = MAX_DIGEST_SZ;
    crv = pFunctionList->C_DigestInit(hSession, &digestmech);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestInit failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Digest(hSession, (CK_BYTE_PTR)plaintext, plainlen,
                                  (CK_BYTE_PTR)digest_1, &digestlen);
    if (crv != CKR_OK) {
        PKM_Error("C_Digest failed returned 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    if (memcmp(digest, digest_1, digestlen) == 0) {
        PKM_LogIt("Digest and digest_1 are equal!\n");
    } else {
        PKM_Error("Digest and digest_1 are not equal!\n");
    }
    crv = pFunctionList->C_Logout(hSession);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Logout succeeded\n");
    } else {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_CloseSession(hSession);
    if (CKR_OK != crv) {
        PKM_Error("C_CloseSession(%lu) returned 0x%08X, %-26s\n",
                  hSession, crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    return crv;
}

/*
* Recover Functions
*/
CK_RV
PKM_RecoverFunctions(CK_FUNCTION_LIST_PTR pFunctionList,
                     CK_SESSION_HANDLE hSession,
                     CK_OBJECT_HANDLE hPubKey, CK_OBJECT_HANDLE hPrivKey,
                     CK_MECHANISM *signMech, const CK_BYTE *pData,
                     CK_ULONG pDataLen)
{
    CK_RV crv = CKR_OK;
    CK_BYTE sig[MAX_SIG_SZ];
    CK_ULONG sigLen = MAX_SIG_SZ;
    CK_BYTE recover[MAX_SIG_SZ];
    CK_ULONG recoverLen = MAX_SIG_SZ;

    PKM_LogIt("PKM_RecoverFunctions started\n");
    NUMTESTS++; /* increment NUMTESTS */

    /* initializes a signature operation,
     *  where the data can be recovered from the signature
     */
    crv = pFunctionList->C_SignRecoverInit(hSession, signMech,
                                           hPrivKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_SignRecoverInit succeeded. \n");
    } else {
        PKM_Error("C_SignRecoverInit failed.\n"
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* signs single-part data,
     * where the data can be recovered from the signature
     */
    crv = pFunctionList->C_SignRecover(hSession, (CK_BYTE *)pData,
                                       pDataLen,
                                       (CK_BYTE *)sig, &sigLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_SignRecover succeeded. \n");
    } else {
        PKM_Error("C_SignRecoverInit failed to create an RSA key pair.\n"
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    /*
     * initializes a verification operation
     *where the data is recovered from the signature
     */
    crv = pFunctionList->C_VerifyRecoverInit(hSession, signMech,
                                             hPubKey);
    if (crv == CKR_OK) {
        PKM_LogIt("C_VerifyRecoverInit succeeded. \n");
    } else {
        PKM_Error("C_VerifyRecoverInit failed.\n"
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    /*
    * verifies a signature on single-part data,
    * where the data is recovered from the signature
    */
    crv = pFunctionList->C_VerifyRecover(hSession, (CK_BYTE *)sig,
                                         sigLen,
                                         (CK_BYTE *)recover, &recoverLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_VerifyRecover succeeded. \n");
    } else {
        PKM_Error("C_VerifyRecover failed.\n"
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    if ((recoverLen == pDataLen) &&
        (memcmp(recover, pData, pDataLen) == 0)) {
        PKM_LogIt("VerifyRecover test case passed\n");
    } else {
        PKM_Error("VerifyRecover test case failed\n");
    }

    return crv;
}
/*
* WrapUnwrap
* wrap the secretkey with the public key.
* unwrap the secretkey with the private key.
*/
CK_RV
PKM_WrapUnwrap(CK_FUNCTION_LIST_PTR pFunctionList,
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hPublicKey,
               CK_OBJECT_HANDLE hPrivateKey,
               CK_MECHANISM *wrapMechanism,
               CK_OBJECT_HANDLE hSecretKey,
               CK_ATTRIBUTE *sKeyTemplate,
               CK_ULONG skeyTempSize)
{
    CK_RV crv = CKR_OK;
    CK_OBJECT_HANDLE hSecretKeyUnwrapped = CK_INVALID_HANDLE;
    CK_BYTE wrappedKey[RSA_BITS/8];
    CK_ULONG ulWrappedKeyLen = 0;

    PKM_LogIt("PKM_WrapUnwrap started\n");
    NUMTESTS++; /* increment NUMTESTS */

    ulWrappedKeyLen = sizeof(wrappedKey);
    crv = pFunctionList->C_WrapKey(
        hSession, wrapMechanism,
        hPublicKey, hSecretKey,
        wrappedKey, &ulWrappedKeyLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_WrapKey succeeded\n");
    } else {
        PKM_Error("C_WrapKey failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_UnwrapKey(
        hSession, wrapMechanism, hPrivateKey,
        wrappedKey, ulWrappedKeyLen, sKeyTemplate,
        skeyTempSize,
        &hSecretKeyUnwrapped);
    if ((crv == CKR_OK) && (hSecretKeyUnwrapped != CK_INVALID_HANDLE)) {
        PKM_LogIt("C_UnwrapKey succeeded\n");
    } else {
        PKM_Error("C_UnwrapKey failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    return crv;
}

/*
 * Tests if the object's attributes match the expected_attrs
 */
CK_RV
PKM_AttributeCheck(CK_FUNCTION_LIST_PTR pFunctionList,
                   CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE obj,
                   CK_ATTRIBUTE_PTR expected_attrs,
                   CK_ULONG expected_attrs_count)
{
    CK_RV crv;
    CK_ATTRIBUTE_PTR tmp_attrs;
    unsigned int i;

    PKM_LogIt("PKM_AttributeCheck started\n");
    NUMTESTS++; /* increment NUMTESTS */

    /* First duplicate the themplate */
    tmp_attrs = malloc(expected_attrs_count * sizeof(CK_ATTRIBUTE));

    if (tmp_attrs == NULL) {
        PKM_Error("Internal test memory failure\n");
        return (CKR_HOST_MEMORY);
    }

    for (i = 0; i < expected_attrs_count; i++) {
        tmp_attrs[i].type = expected_attrs[i].type;
        tmp_attrs[i].ulValueLen = expected_attrs[i].ulValueLen;

        /* Don't give away the expected one. just zeros */
        tmp_attrs[i].pValue = calloc(expected_attrs[i].ulValueLen, 1);

        if (tmp_attrs[i].pValue == NULL) {
            unsigned int j;
            for (j = 0; j < i; j++)
                free(tmp_attrs[j].pValue);

            free(tmp_attrs);
            printf("Internal test memory failure\n");
            return (CKR_HOST_MEMORY);
        }
    }

    /* then get the attributes from the object */
    crv = pFunctionList->C_GetAttributeValue(hSession, obj, tmp_attrs,
                                             expected_attrs_count);
    if (crv != CKR_OK) {
        PKM_Error("C_GetAttributeValue failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        crv = CKR_FUNCTION_FAILED;
        goto out;
    }

    /* Finally compare with the expected ones */
    for (i = 0; i < expected_attrs_count; i++) {

        if (memcmp(tmp_attrs[i].pValue, expected_attrs[i].pValue,
                   expected_attrs[i].ulValueLen) != 0) {
            PKM_LogIt("comparing attribute type 0x%x with expected  0x%x\n",
                      tmp_attrs[i].type, expected_attrs[i].type);
            PKM_LogIt("comparing attribute type value 0x%x with expected 0x%x\n",
                      tmp_attrs[i].pValue, expected_attrs[i].pValue);
            /* don't report error at this time */
        }
    }

out:
    for (i = 0; i < expected_attrs_count; i++)
        free(tmp_attrs[i].pValue);
    free(tmp_attrs);
    return (crv);
}

/*
 * Check the validity of a mech
 */
CK_RV
PKM_MechCheck(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession,
              CK_MECHANISM_TYPE mechType, CK_FLAGS flags,
              CK_BBOOL check_sizes, CK_ULONG minkeysize, CK_ULONG maxkeysize)
{
    CK_SESSION_INFO sess_info;
    CK_MECHANISM_INFO mech_info;
    CK_RV crv;

    PKM_LogIt("PKM_MechCheck started\n");
    NUMTESTS++; /* increment NUMTESTS */

    if ((crv = pFunctionList->C_GetSessionInfo(hSession, &sess_info)) !=
        CKR_OK) {
        PKM_Error("C_GetSessionInfo failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return (CKR_FUNCTION_FAILED);
    }

    crv = pFunctionList->C_GetMechanismInfo(0, mechType,
                                            &mech_info);

    crv = pFunctionList->C_GetMechanismInfo(sess_info.slotID, mechType,
                                            &mech_info);

    if (crv != CKR_OK) {
        PKM_Error("C_GetMechanismInfo failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return (CKR_FUNCTION_FAILED);
    }

    if ((mech_info.flags & flags) == 0) {
        PKM_Error("0x%x flag missing from mech\n", flags);
        return (CKR_MECHANISM_INVALID);
    }
    if (!check_sizes)
        return (CKR_OK);

    if (mech_info.ulMinKeySize != minkeysize) {
        PKM_Error("Bad MinKeySize %d expected %d\n", mech_info.ulMinKeySize,
                  minkeysize);
        return (CKR_MECHANISM_INVALID);
    }
    if (mech_info.ulMaxKeySize != maxkeysize) {
        PKM_Error("Bad MaxKeySize %d expected %d\n", mech_info.ulMaxKeySize,
                  maxkeysize);
        return (CKR_MECHANISM_INVALID);
    }
    return (CKR_OK);
}

/*
 * Can be called with a non-null premaster_key_len for the
 * *_DH mechanisms. In that case, no checking for the matching of
 * the expected results is done.
 * The rnd argument tells which correct/bogus randomInfo to use.
 */
CK_RV
PKM_TLSMasterKeyDerive(CK_FUNCTION_LIST_PTR pFunctionList,
                       CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                       CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen,
                       CK_MECHANISM_TYPE mechType,
                       enum_random_t rnd)
{
    CK_SESSION_HANDLE hSession;
    CK_RV crv;
    CK_MECHANISM mk_mech;
    CK_VERSION version;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    CK_BBOOL derive_bool = true;
    CK_ATTRIBUTE attrs[4];
    CK_ULONG attrs_count = 4;
    CK_OBJECT_HANDLE pmk_obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE mk_obj = CK_INVALID_HANDLE;
    CK_SSL3_MASTER_KEY_DERIVE_PARAMS mkd_params;
    CK_MECHANISM skmd_mech;

    CK_BBOOL isDH = false;

    PKM_LogIt("PKM_TLSMasterKeyDerive started\n");
    NUMTESTS++; /* increment NUMTESTS */

    attrs[0].type = CKA_CLASS;
    attrs[0].pValue = &class;
    attrs[0].ulValueLen = sizeof(class);
    attrs[1].type = CKA_KEY_TYPE;
    attrs[1].pValue = &type;
    attrs[1].ulValueLen = sizeof(type);
    attrs[2].type = CKA_DERIVE;
    attrs[2].pValue = &derive_bool;
    attrs[2].ulValueLen = sizeof(derive_bool);
    attrs[3].type = CKA_VALUE;
    attrs[3].pValue = NULL;
    attrs[3].ulValueLen = 0;

    crv = pFunctionList->C_OpenSession(pSlotList[slotID], CKF_SERIAL_SESSION,
                                       NULL, NULL, &hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_OpenSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Login(hSession, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Login with correct password succeeded\n");
    } else {
        PKM_Error("C_Login with correct password failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* Before all, check if the mechanism is supported correctly */
    if (MODE == FIPSMODE) {
        crv = PKM_MechCheck(pFunctionList, hSession, mechType, CKF_DERIVE, false,
                            0, 0);
        if (crv != CKR_OK) {
            PKM_Error("PKM_MechCheck failed with 0x%08X, %-26s\n", crv,
                      PKM_CK_RVtoStr(crv));
            return (crv);
        }
    }

    mk_mech.mechanism = mechType;
    mk_mech.pParameter = &mkd_params;
    mk_mech.ulParameterLen = sizeof(mkd_params);

    switch (mechType) {
        case CKM_TLS_MASTER_KEY_DERIVE_DH:
            isDH = true;
        /* FALLTHRU */
        case CKM_TLS_MASTER_KEY_DERIVE:
            attrs[3].pValue = NULL;
            attrs[3].ulValueLen = 0;

            mkd_params.RandomInfo.pClientRandom = (unsigned char *)TLSClientRandom;
            mkd_params.RandomInfo.ulClientRandomLen =
                sizeof(TLSClientRandom);
            mkd_params.RandomInfo.pServerRandom = (unsigned char *)TLSServerRandom;
            mkd_params.RandomInfo.ulServerRandomLen =
                sizeof(TLSServerRandom);
            break;
    }
    mkd_params.pVersion = (!isDH) ? &version : NULL;

    /* First create the pre-master secret key */

    skmd_mech.mechanism = CKM_SSL3_PRE_MASTER_KEY_GEN;
    skmd_mech.pParameter = &mkd_params;
    skmd_mech.ulParameterLen = sizeof(mkd_params);

    crv = pFunctionList->C_GenerateKey(hSession, &skmd_mech,
                                       attrs,
                                       attrs_count,
                                       &pmk_obj);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateKey succeeded\n");
    } else {
        PKM_Error("C_GenerateKey failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    /* Test the bad cases */
    switch (rnd) {
        case CORRECT:
            goto correct;

        case BOGUS_CLIENT_RANDOM:
            mkd_params.RandomInfo.pClientRandom = NULL;
            break;

        case BOGUS_CLIENT_RANDOM_LEN:
            mkd_params.RandomInfo.ulClientRandomLen = 0;
            break;

        case BOGUS_SERVER_RANDOM:
            mkd_params.RandomInfo.pServerRandom = NULL;
            break;

        case BOGUS_SERVER_RANDOM_LEN:
            mkd_params.RandomInfo.ulServerRandomLen = 0;
            break;
    }
    crv = pFunctionList->C_DeriveKey(hSession, &mk_mech, pmk_obj, NULL, 0,
                                     &mk_obj);
    if (crv != CKR_MECHANISM_PARAM_INVALID) {
        PKM_LogIt("C_DeriveKey returned as EXPECTED with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
    } else {
        PKM_Error("C_DeriveKey did not fail  with  bad data \n");
    }
    goto out;

correct:
    /* Now derive the master secret key */
    crv = pFunctionList->C_DeriveKey(hSession, &mk_mech, pmk_obj, NULL, 0,
                                     &mk_obj);
    if (crv == CKR_OK) {
        PKM_LogIt("C_DeriveKey succeeded\n");
    } else {
        PKM_Error("C_DeriveKey failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

out:
    if (pmk_obj != CK_INVALID_HANDLE)
        (void)pFunctionList->C_DestroyObject(hSession, pmk_obj);
    if (mk_obj != CK_INVALID_HANDLE)
        (void)pFunctionList->C_DestroyObject(hSession, mk_obj);
    crv = pFunctionList->C_Logout(hSession);

    if (crv == CKR_OK) {
        PKM_LogIt("C_Logout succeeded\n");
    } else {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_CloseSession(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    return (crv);
}

CK_RV
PKM_TLSKeyAndMacDerive(CK_FUNCTION_LIST_PTR pFunctionList,
                       CK_SLOT_ID *pSlotList, CK_ULONG slotID,
                       CK_UTF8CHAR_PTR pwd, CK_ULONG pwdLen,
                       CK_MECHANISM_TYPE mechType, enum_random_t rnd)
{
    CK_SESSION_HANDLE hSession;
    CK_RV crv;
    CK_MECHANISM kmd_mech;
    CK_MECHANISM skmd_mech;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    CK_BBOOL derive_bool = true;
    CK_BBOOL sign_bool = true, verify_bool = true;
    CK_BBOOL encrypt_bool = true, decrypt_bool = true;
    CK_ULONG value_len;

    /*
     * We arrange this template so that:
     * . Attributes 0-6 are good for a MAC key comparison template.
     * . Attributes 2-5 are good for the master key creation template.
     * . Attributes 3-8 are good for a cipher key comparison template.
     */
    CK_ATTRIBUTE attrs[9];

    CK_OBJECT_HANDLE mk_obj = CK_INVALID_HANDLE;
    CK_SSL3_KEY_MAT_PARAMS km_params;
    CK_SSL3_KEY_MAT_OUT kmo;
    CK_BYTE IVClient[8];
    CK_BYTE IVServer[8];

    PKM_LogIt("PKM_TLSKeyAndMacDerive started\n");
    NUMTESTS++; /* increment NUMTESTS */

    attrs[0].type = CKA_SIGN;
    attrs[0].pValue = &sign_bool;
    attrs[0].ulValueLen = sizeof(sign_bool);
    attrs[1].type = CKA_VERIFY;
    attrs[1].pValue = &verify_bool;
    attrs[1].ulValueLen = sizeof(verify_bool);
    attrs[2].type = CKA_KEY_TYPE;
    attrs[2].pValue = &type;
    attrs[2].ulValueLen = sizeof(type);
    attrs[3].type = CKA_CLASS;
    attrs[3].pValue = &class;
    attrs[3].ulValueLen = sizeof(class);
    attrs[4].type = CKA_DERIVE;
    attrs[4].pValue = &derive_bool;
    attrs[4].ulValueLen = sizeof(derive_bool);
    attrs[5].type = CKA_VALUE;
    attrs[5].pValue = NULL;
    attrs[5].ulValueLen = 0;
    attrs[6].type = CKA_VALUE_LEN;
    attrs[6].pValue = &value_len;
    attrs[6].ulValueLen = sizeof(value_len);
    attrs[7].type = CKA_ENCRYPT;
    attrs[7].pValue = &encrypt_bool;
    attrs[7].ulValueLen = sizeof(encrypt_bool);
    attrs[8].type = CKA_DECRYPT;
    attrs[8].pValue = &decrypt_bool;
    attrs[8].ulValueLen = sizeof(decrypt_bool);

    crv = pFunctionList->C_OpenSession(pSlotList[slotID], CKF_SERIAL_SESSION,
                                       NULL, NULL, &hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_OpenSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_Login(hSession, CKU_USER, pwd, pwdLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Login with correct password succeeded\n");
    } else {
        PKM_Error("C_Login with correct password failed "
                  "with 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* Before all, check if the mechanism is supported correctly */
    if (MODE == FIPSMODE) {
        crv = PKM_MechCheck(pFunctionList, hSession, mechType, CKF_DERIVE,
                            CK_TRUE, 48, 48);

        if (crv != CKR_OK) {
            PKM_Error("PKM_MechCheck failed with 0x%08X, %-26s\n", crv,
                      PKM_CK_RVtoStr(crv));
            return (crv);
        }
    }
    kmd_mech.mechanism = mechType;
    kmd_mech.pParameter = &km_params;
    kmd_mech.ulParameterLen = sizeof(km_params);

    km_params.ulMacSizeInBits = 128; /* an MD5 based MAC */
    km_params.ulKeySizeInBits = 192; /* 3DES key size */
    km_params.ulIVSizeInBits = 64;   /* 3DES block size */
    km_params.pReturnedKeyMaterial = &kmo;
    km_params.bIsExport = false;
    kmo.hClientMacSecret = CK_INVALID_HANDLE;
    kmo.hServerMacSecret = CK_INVALID_HANDLE;
    kmo.hClientKey = CK_INVALID_HANDLE;
    kmo.hServerKey = CK_INVALID_HANDLE;
    kmo.pIVClient = IVClient;
    kmo.pIVServer = IVServer;

    skmd_mech.mechanism = CKM_SSL3_PRE_MASTER_KEY_GEN;
    skmd_mech.pParameter = &km_params;
    skmd_mech.ulParameterLen = sizeof(km_params);

    crv = pFunctionList->C_GenerateKey(hSession, &skmd_mech,
                                       &attrs[2],
                                       4,
                                       &mk_obj);
    if (crv == CKR_OK) {
        PKM_LogIt("C_GenerateKey succeeded\n");
    } else {
        PKM_Error("C_GenerateKey failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    attrs[5].pValue = NULL;
    attrs[5].ulValueLen = 0;

    km_params.RandomInfo.pClientRandom = (unsigned char *)TLSClientRandom;
    km_params.RandomInfo.ulClientRandomLen =
        sizeof(TLSClientRandom);
    km_params.RandomInfo.pServerRandom = (unsigned char *)TLSServerRandom;
    km_params.RandomInfo.ulServerRandomLen =
        sizeof(TLSServerRandom);

    /* Test the bad cases */
    switch (rnd) {
        case CORRECT:
            goto correct;

        case BOGUS_CLIENT_RANDOM:
            km_params.RandomInfo.pClientRandom = NULL;
            break;

        case BOGUS_CLIENT_RANDOM_LEN:
            km_params.RandomInfo.ulClientRandomLen = 0;
            break;

        case BOGUS_SERVER_RANDOM:
            km_params.RandomInfo.pServerRandom = NULL;
            break;

        case BOGUS_SERVER_RANDOM_LEN:
            km_params.RandomInfo.ulServerRandomLen = 0;
            break;
    }
    crv = pFunctionList->C_DeriveKey(hSession, &kmd_mech, mk_obj, NULL, 0,
                                     NULL);
    if (crv != CKR_MECHANISM_PARAM_INVALID) {
        PKM_Error("key materials derivation returned unexpected "
                  "error 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        (void)pFunctionList->C_DestroyObject(hSession, mk_obj);
        return (CKR_FUNCTION_FAILED);
    }
    return (CKR_OK);

correct:
    /*
     * Then use the master key and the client 'n server random data to
     * derive the key materials
     */
    crv = pFunctionList->C_DeriveKey(hSession, &kmd_mech, mk_obj, NULL, 0,
                                     NULL);
    if (crv != CKR_OK) {
        PKM_Error("Cannot derive the key materials, crv 0x%08X, %-26s\n",
                  crv, PKM_CK_RVtoStr(crv));
        (void)pFunctionList->C_DestroyObject(hSession, mk_obj);
        return (crv);
    }

    if (mk_obj != CK_INVALID_HANDLE)
        (void)pFunctionList->C_DestroyObject(hSession, mk_obj);
    if (kmo.hClientMacSecret != CK_INVALID_HANDLE)
        (void)pFunctionList->C_DestroyObject(hSession, kmo.hClientMacSecret);
    if (kmo.hServerMacSecret != CK_INVALID_HANDLE)
        (void)pFunctionList->C_DestroyObject(hSession, kmo.hServerMacSecret);
    if (kmo.hClientKey != CK_INVALID_HANDLE)
        (void)pFunctionList->C_DestroyObject(hSession, kmo.hClientKey);
    if (kmo.hServerKey != CK_INVALID_HANDLE)
        (void)pFunctionList->C_DestroyObject(hSession, kmo.hServerKey);

    crv = pFunctionList->C_Logout(hSession);
    if (crv == CKR_OK) {
        PKM_LogIt("C_Logout succeeded\n");
    } else {
        PKM_Error("C_Logout failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_CloseSession(hSession);
    if (crv != CKR_OK) {
        PKM_Error("C_CloseSession failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    return (crv);
}

CK_RV
PKM_DualFuncSign(CK_FUNCTION_LIST_PTR pFunctionList,
                 CK_SESSION_HANDLE hRwSession,
                 CK_OBJECT_HANDLE publicKey, CK_OBJECT_HANDLE privateKey,
                 CK_MECHANISM *sigMech,
                 CK_OBJECT_HANDLE secretKey, CK_MECHANISM *cryptMech,
                 const CK_BYTE *pData, CK_ULONG pDataLen)
{

    CK_RV crv = CKR_OK;
    CK_BYTE encryptedData[MAX_CIPHER_SZ];
    CK_ULONG ulEncryptedDataLen = 0;
    CK_ULONG ulLastUpdateSize = 0;
    CK_BYTE sig[MAX_SIG_SZ];
    CK_ULONG ulSigLen = 0;
    CK_BYTE data[MAX_DATA_SZ];
    CK_ULONG ulDataLen = 0;

    memset(encryptedData, 0, sizeof(encryptedData));
    memset(sig, 0, sizeof(sig));
    memset(data, 0, sizeof(data));

    PKM_LogIt("PKM_DualFuncSign started\n");
    NUMTESTS++; /* increment NUMTESTS */

    /* Check that the mechanism is Multi-part */
    if (sigMech->mechanism == CKM_DSA || sigMech->mechanism == CKM_RSA_PKCS) {
        PKM_Error("PKM_DualFuncSign must be called with a Multi-part "
                  "operation mechanism\n");
        return CKR_DEVICE_ERROR;
    }

    /* Sign and Encrypt */
    if (privateKey == 0 && publicKey == 0) {
        crv = pFunctionList->C_SignInit(hRwSession, sigMech, secretKey);
        if (crv != CKR_OK) {
            PKM_Error("C_SignInit failed with 0x%08X, %-26s\n", crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }
    } else {
        crv = pFunctionList->C_SignInit(hRwSession, sigMech, privateKey);
        if (crv != CKR_OK) {
            PKM_Error("C_SignInit failed with 0x%08X, %-26s\n", crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }
    }
    crv = pFunctionList->C_EncryptInit(hRwSession, cryptMech, secretKey);
    if (crv != CKR_OK) {
        PKM_Error("C_EncryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    ulEncryptedDataLen = sizeof(encryptedData);
    crv = pFunctionList->C_SignEncryptUpdate(hRwSession, (CK_BYTE *)pData,
                                             pDataLen,
                                             encryptedData,
                                             &ulEncryptedDataLen);
    if (crv != CKR_OK) {
        PKM_Error("C_Sign failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    ulLastUpdateSize = sizeof(encryptedData) - ulEncryptedDataLen;
    crv = pFunctionList->C_EncryptFinal(hRwSession,
                                        (CK_BYTE *)&encryptedData[ulEncryptedDataLen], &ulLastUpdateSize);
    if (crv != CKR_OK) {
        PKM_Error("C_EncryptFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    ulEncryptedDataLen = ulEncryptedDataLen + ulLastUpdateSize;
    ulSigLen = sizeof(sig);
    crv = pFunctionList->C_SignFinal(hRwSession, sig, &ulSigLen);
    if (crv != CKR_OK) {
        PKM_Error("C_SignFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* Decrypt and Verify */

    crv = pFunctionList->C_DecryptInit(hRwSession, cryptMech, secretKey);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    crv = pFunctionList->C_VerifyInit(hRwSession, sigMech,
                                      publicKey);
    if (crv != CKR_OK) {
        PKM_Error("C_VerifyInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    ulDataLen = sizeof(data);
    crv = pFunctionList->C_DecryptVerifyUpdate(hRwSession,
                                               encryptedData,
                                               ulEncryptedDataLen,
                                               data, &ulDataLen);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptVerifyUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    ulLastUpdateSize = sizeof(data) - ulDataLen;
    /* Get last little piece of plaintext.  Should have length 0 */
    crv = pFunctionList->C_DecryptFinal(hRwSession, &data[ulDataLen],
                                        &ulLastUpdateSize);
    if (crv != CKR_OK) {
        PKM_Error("C_DecryptFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    if (ulLastUpdateSize != 0) {
        crv = pFunctionList->C_VerifyUpdate(hRwSession, &data[ulDataLen],
                                            ulLastUpdateSize);
        if (crv != CKR_OK) {
            PKM_Error("C_DecryptFinal failed with 0x%08X, %-26s\n", crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }
    }
    ulDataLen = ulDataLen + ulLastUpdateSize;

    /* input for the verify operation is the decrypted data */
    crv = pFunctionList->C_VerifyFinal(hRwSession, sig, ulSigLen);
    if (crv == CKR_OK) {
        PKM_LogIt("C_VerifyFinal succeeded\n");
    } else {
        PKM_Error("C_VerifyFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* Comparison of Decrypted data with inputed data */
    if ((ulDataLen == pDataLen) &&
        (memcmp(data, pData, pDataLen) == 0)) {
        PKM_LogIt("PKM_DualFuncSign decrypt test case passed\n");
    } else {
        PKM_Error("PKM_DualFuncSign derypt test case failed\n");
    }

    return crv;
}

CK_RV
PKM_Digest(CK_FUNCTION_LIST_PTR pFunctionList,
           CK_SESSION_HANDLE hSession,
           CK_MECHANISM *digestMech, CK_OBJECT_HANDLE hSecretKey,
           const CK_BYTE *pData, CK_ULONG pDataLen)
{
    CK_RV crv = CKR_OK;
    CK_BYTE digest1[MAX_DIGEST_SZ];
    CK_ULONG digest1Len = 0;
    CK_BYTE digest2[MAX_DIGEST_SZ];
    CK_ULONG digest2Len = 0;

    /* Tested with CKM_SHA_1, CKM_SHA224, CKM_SHA256, CKM_SHA384, CKM_SHA512 */

    memset(digest1, 0, sizeof(digest1));
    memset(digest2, 0, sizeof(digest2));

    PKM_LogIt("PKM_Digest started\n");
    NUMTESTS++; /* increment NUMTESTS */

    crv = pFunctionList->C_DigestInit(hSession, digestMech);
    if (crv != CKR_OK) {
        PKM_Error("C_SignInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }
    digest1Len = sizeof(digest1);
    crv = pFunctionList->C_Digest(hSession, (CK_BYTE *)pData, pDataLen,
                                  digest1, &digest1Len);
    if (crv != CKR_OK) {
        PKM_Error("C_Sign failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_DigestInit(hSession, digestMech);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestInit failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    crv = pFunctionList->C_DigestUpdate(hSession, (CK_BYTE *)pData, pDataLen);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestUpdate failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    /* C_DigestKey continues a multiple-part message-digesting operation by*/
    /* digesting the value of a secret key. (only used with C_DigestUpdate)*/
    if (hSecretKey != 0) {
        crv = pFunctionList->C_DigestKey(hSession, hSecretKey);
        if (crv != CKR_OK) {
            PKM_Error("C_DigestKey failed with 0x%08X, %-26s\n", crv,
                      PKM_CK_RVtoStr(crv));
            return crv;
        }
    }

    digest2Len = sizeof(digest2);
    crv = pFunctionList->C_DigestFinal(hSession, digest2, &digest2Len);
    if (crv != CKR_OK) {
        PKM_Error("C_DigestFinal failed with 0x%08X, %-26s\n", crv,
                  PKM_CK_RVtoStr(crv));
        return crv;
    }

    if (hSecretKey == 0) {
        /* did not digest a secret key so digests should equal */
        if ((digest1Len == digest2Len) &&
            (memcmp(digest1, digest2, digest1Len) == 0)) {
            PKM_LogIt("Single and Multiple-part message digest "
                      "operations successful\n");
        } else {
            PKM_Error("Single and Multiple-part message digest "
                      "operations failed\n");
        }
    } else {
        if (digest1Len == digest2Len) {
            PKM_LogIt("PKM_Digest Single and Multiple-part message digest "
                      "operations successful\n");
        } else {
            PKM_Error("PKM_Digest Single and Multiple-part message digest "
                      "operations failed\n");
        }
    }

    return crv;
}

char *
PKM_FilePasswd(char *pwFile)
{
    unsigned char phrase[200];
    PRFileDesc *fd;
    PRInt32 nb;
    int i;

    if (!pwFile)
        return 0;

    fd = PR_Open(pwFile, PR_RDONLY, 0);
    if (!fd) {
        fprintf(stderr, "No password file \"%s\" exists.\n", pwFile);
        return NULL;
    }

    nb = PR_Read(fd, phrase, sizeof(phrase));

    PR_Close(fd);
    /* handle the Windows EOL case */
    i = 0;
    while (phrase[i] != '\r' && phrase[i] != '\n' && i < nb)
        i++;
    phrase[i] = '\0';
    if (nb == 0) {
        fprintf(stderr, "password file contains no data\n");
        return NULL;
    }
    return (char *)strdup((char *)phrase);
}

void
PKM_Help()
{
    PRFileDesc *debug_out = PR_GetSpecialFD(PR_StandardError);
    PR_fprintf(debug_out, "pk11mode test program usage:\n");
    PR_fprintf(debug_out, "\t-f <file>   Password File : echo pw > file \n");
    PR_fprintf(debug_out, "\t-F          Disable Unix fork tests\n");
    PR_fprintf(debug_out, "\t-n          Non Fips Mode \n");
    PR_fprintf(debug_out, "\t-d <path>   Database path location\n");
    PR_fprintf(debug_out, "\t-p <prefix> DataBase prefix\n");
    PR_fprintf(debug_out, "\t-v          verbose\n");
    PR_fprintf(debug_out, "\t-h          this help message\n");
    exit(1);
}

void
PKM_CheckPath(char *string)
{
    char *src;
    char *dest;

    /*
   * windows support convert any back slashes to
   * forward slashes.
   */
    for (src = string, dest = string; *src; src++, dest++) {
        if (*src == '\\') {
            *dest = '/';
        }
    }
    dest--;
    /* if the last char is a / set it to 0 */
    if (*dest == '/')
        *dest = 0;
}

CK_RV
PKM_ForkCheck(int expected, CK_FUNCTION_LIST_PTR fList,
              PRBool forkAssert, CK_C_INITIALIZE_ARGS_NSS *initArgs)
{
    CK_RV crv = CKR_OK;
#ifndef NO_FORK_CHECK
    int rc = -1;
    pid_t child, ret;
    PKM_LogIt("PKM_ForkCheck started\n");
    NUMTESTS++; /* increment NUMTESTS */
    if (forkAssert) {
        putenv("NSS_STRICT_NOFORK=1");
    } else {
        putenv("NSS_STRICT_NOFORK=0");
    }
    child = fork();
    switch (child) {
        case -1:
            PKM_Error("Fork failed.\n");
            crv = CKR_DEVICE_ERROR;
            break;
        case 0:
            if (fList) {
                if (!initArgs) {
                    /* If softoken is loaded, make a PKCS#11 call to C_GetTokenInfo
                 * in the child. This call should always fail.
                 * If softoken is uninitialized,
                 * it fails with CKR_CRYPTOKI_NOT_INITIALIZED.
                 * If it was initialized in the parent, the fork check should
                 * kick in, and make it return CKR_DEVICE_ERROR.
                 */
                    CK_RV child_crv = fList->C_GetTokenInfo(0, NULL);
                    exit(child_crv & 255);
                } else {
                    /* If softoken is loaded, make a PKCS#11 call to C_Initialize
                 * in the child. This call should always fail.
                 * If softoken is uninitialized, this should succeed.
                 * If it was initialized in the parent, the fork check should
                 * kick in, and make it return CKR_DEVICE_ERROR.
                 */
                    CK_RV child_crv = fList->C_Initialize(initArgs);
                    if (CKR_OK == child_crv) {
                        child_crv = fList->C_Finalize(NULL);
                    }
                    exit(child_crv & 255);
                }
            }
            exit(expected & 255);
        default:
            PKM_LogIt("Fork succeeded.\n\n");
            ret = wait(&rc);
            if (ret != child || (!WIFEXITED(rc)) ||
                ((expected & 255) != (WEXITSTATUS(rc) & 255))) {
                int retStatus = -1;
                if (WIFEXITED(rc)) {
                    retStatus = WEXITSTATUS(rc);
                }
                PKM_Error("Child misbehaved.\n");
                printf("Child return status : %d.\n", retStatus & 255);
                crv = CKR_DEVICE_ERROR;
            }
            break;
    }
#endif
    return crv;
}
