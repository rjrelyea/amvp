/*
 *  NSS Module tests. The actual tests are usually external applications.
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <prtypes.h>
#include <hasht.h>
#include "amvp.h"
#include "app_lcl.h"
#include "midbg.h"
#include "os_util.h"


/*************************************************************************
 *  Debugger breakpoints for our debug based tests.
 *
 ************************************************************************/

/* this is used to generically handle most post operations */
struct load_breakpoint_info {
    const char *post_entry; /* symbol for the next breakpoint */
    const char *post_label; /* label for the next breakpoint */
    unsigned long *pflags;  /* pointer to the flags variable */
    unsigned long set_flags; /* flag to set at this breakpoint */
    unsigned long post_flags; /* flag to set at the next breakpoint */
};

/* POST TESTS */
#define FLAG_SOFTOKEN_LOADED               0x0000000000000001UL
#define FLAG_SOFTOKEN_POST_CALLED          0x0000000000000002UL
#define FLAG_SOFTOKEN_POST_FINISHED_LOAD   0x0000000000000004UL
#define FLAG_FREEBL_LOADED                 0x0000000000000010UL
#define FLAG_FREEBL_POST_CALLED            0x0000000000000020Ul
#define FLAG_FREEBL_POST_FINISHED_LOAD     0x0000000000000040UL
#define FLAG_DBM_LOADED                    0x0000000000000100UL
#define FLAG_DBM_POST_CALLED               0x0000000000000200UL
#define FLAG_DBM_POST_FINISHED_LOAD        0x0000000000000400UL
#define FLAG_DRBG_POST_CALLED              0x0000000000001000UL
#define FLAG_DES3_POST_CALLED              0x0000000000001000UL
#define FLAG_AES_128_POST_CALLED           0x0000000000001000UL
#define FLAG_AES_192_POST_CALLED           0x0000000000002000UL
#define FLAG_AES_256_POST_CALLED           0x0000000000004000UL
#define FLAG_SHA_POST_CALLED               0x0000000000008000UL
#define FLAG_HMAC_SHA_1_POST_CALLED        0x0000000000010000UL
#define FLAG_HMAC_SHA_224_POST_CALLED      0x0000000000020000UL
#define FLAG_HMAC_SHA_256_POST_CALLED      0x0000000000040000UL
#define FLAG_HMAC_SHA_384_POST_CALLED      0x0000000000080000UL
#define FLAG_HMAC_SHA_512_POST_CALLED      0x0000000000100000UL
#define FLAG_RSA_1_POST_CALLED             0x0000000000200000UL
#define FLAG_DSA_POST_CALLED               0x0000000000400000UL
#define FLAG_RSA_2_POST_CALLED             0x0000000001000000UL
#define FLAG_ECDSA_POST_CALLED             0x0000000002000000UL
#define FLAG_RSA_CHECK_CALLED              0x0000000010000000UL
#define FLAG_EXPECTED_FLAGS                0x0000000011FFF777UL


/* handle generic handle posts. simple update the flags */
AMVP_RESULT 
handle_post(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
		const char *async_reply, void *args)
{
    struct load_breakpoint_info *info = (struct load_breakpoint_info *)args;

    /* indicate that post was executed */
    *(info->pflags) |= info->post_flags;
    return AMVP_SUCCESS;
}

/* Handle the various Known answer tests that need special handling */

/* There are multiple calls to the aes with different key sizes, look
 * up the key size before setting our flag and printing our log entry */
AMVP_RESULT 
handle_aes_post(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
		const char *arcyn_reply, void *args)
{
    struct load_breakpoint_info *info = (struct load_breakpoint_info *)args;
    AMVP_RESULT  rc;
    unsigned long key_size; 
    char buf[1024];

    rc = midbg_get_scalar(dbgSess, "aes_key_size", sizeof(int), &key_size);
    if (rc != AMVP_SUCCESS) {
	return rc;
    }
    key_size = key_size*8;
    
    switch (key_size) {
    case 128:
	   midbg_log(dbgSess, "# POST AES keysize=128\n"); 
    	   *(info->pflags) |= FLAG_AES_128_POST_CALLED;
	   break;
    case 192:
	   midbg_log(dbgSess, "# POST AES keysize=192\n"); 
    	   *(info->pflags) |= FLAG_AES_192_POST_CALLED;
	   break;
    case 256:
	   midbg_log(dbgSess, "# POST AES keysize=256\n"); 
    	   *(info->pflags) |= FLAG_AES_256_POST_CALLED;
	   break;
    default:
	   sprintf(buf,"# POST AES keysize=%ld (unrecognized key size)\n",
					key_size); 

	   midbg_log(dbgSess, buf); 
	   break;
    }
    return AMVP_SUCCESS;
}

/* Like AES, there are multiple calls to the hmac with different hash sizes,
 * look up the key size before setting our flag and printing oru log entry */
AMVP_RESULT 
handle_hmac_post(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
		const char *arcyn_reply, void *args)
{
    struct load_breakpoint_info *info = (struct load_breakpoint_info *)args;
    AMVP_RESULT  rc;
    unsigned long hashLong;
    HASH_HashType hashAlg; 
    char buf[1024];

    rc = midbg_get_scalar(dbgSess, "(int)hashAlg", 
			  sizeof(HASH_HashType), &hashLong);
    if (rc != AMVP_SUCCESS) {
	return rc;
    }
    hashAlg = (HASH_HashType) hashLong;
    
    switch (hashAlg) {
    case HASH_AlgNULL:
	   midbg_log(dbgSess, "# POST HMAC-NULL (not FIPS)\n"); 
	   break;
    case HASH_AlgMD2:
	   midbg_log(dbgSess, "# POST HMAC-MD2 (not FIPS)\n"); 
	   break;
    case HASH_AlgMD5:
	   midbg_log(dbgSess, "# POST HMAC-MD5 (not FIPS)\n"); 
	   break;
    case HASH_AlgSHA1:
	   midbg_log(dbgSess, "# POST HMAC-SHA1\n"); 
    	   *(info->pflags) |= FLAG_HMAC_SHA_1_POST_CALLED;
	   break;
    case HASH_AlgSHA224:
	   midbg_log(dbgSess, "# POST HMAC-SHA224\n"); 
    	   *(info->pflags) |= FLAG_HMAC_SHA_224_POST_CALLED;
	   break;
    case HASH_AlgSHA256:
	   midbg_log(dbgSess, "# POST HMAC-SHA256\n"); 
    	   *(info->pflags) |= FLAG_HMAC_SHA_256_POST_CALLED;
	   break;
    case HASH_AlgSHA384:
	   midbg_log(dbgSess, "# POST HMAC-SHA384\n"); 
    	   *(info->pflags) |= FLAG_HMAC_SHA_384_POST_CALLED;
	   break;
    case HASH_AlgSHA512:
	   midbg_log(dbgSess, "# POST HMAC-SHA512\n"); 
    	   *(info->pflags) |= FLAG_HMAC_SHA_512_POST_CALLED;
	   break;
    default:
	   sprintf(buf,"# POST HMAC unkown type=%d\n", hashAlg); 
	   midbg_log(dbgSess, buf); 
	   break;
    }
    return AMVP_SUCCESS;
}

/* on library load, set up the additional breakpoints for the library */
/* This can also be used anytime you need a cascade breakpoint (call a
 * breakpoint to set a new breakpoint. flags are set on the initial call
 * and the folloing call */
AMVP_RESULT 
handle_lib_load(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
		const char *async_reply, void *args)
{
    struct load_breakpoint_info *info = (struct load_breakpoint_info *)args;

    /* indicate that we were loaded */
    *(info->pflags) |= info->set_flags;

    /* insert a new breakpoint for the post for this library */
    return midbg_add_breakpoint(dbgSess, "break-insert", info->post_entry,
		    info->post_label, handle_post, info);
}


/* Freebl needs to also set the breakpoints for the known answer tests */
AMVP_RESULT 
handle_lib_freebl_load(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
		const char *async_reply, void *args)
{
    AMVP_RESULT rv;
    struct load_breakpoint_info *info = (struct load_breakpoint_info *)args;
    static struct load_breakpoint_info drbg_info;
    static struct load_breakpoint_info des3_info;
    static struct load_breakpoint_info aes_info;
    static struct load_breakpoint_info sha_info;
    static struct load_breakpoint_info hmac_info;
    static struct load_breakpoint_info rsa_info;
    static struct load_breakpoint_info dsa_info;
    static struct load_breakpoint_info ecdsa_info;
    drbg_info = des3_info = aes_info = sha_info = hmac_info = rsa_info
     = dsa_info = ecdsa_info = *info;
    drbg_info.post_flags = FLAG_DRBG_POST_CALLED;
    des3_info.post_flags = FLAG_DES3_POST_CALLED;
    aes_info.post_flags = FLAG_AES_128_POST_CALLED;
    sha_info.post_flags = FLAG_SHA_POST_CALLED;
    hmac_info.post_flags = FLAG_HMAC_SHA_1_POST_CALLED;
    rsa_info.post_flags = FLAG_RSA_1_POST_CALLED;
    dsa_info.post_flags = FLAG_DSA_POST_CALLED;
    ecdsa_info.post_flags = FLAG_ECDSA_POST_CALLED;

    rv = handle_lib_load(dbgSess, breakpoint, async_reply, args);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    /* Add all the selftests */
    rv = midbg_add_breakpoint(dbgSess, "break-insert", 
	"freebl_fips_RNG_PowerUpSelfTest",
	"Power On Self Test for drgb", handle_post, &drbg_info);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = midbg_add_breakpoint(dbgSess, "break-insert", 
	"freebl_fips_DES3_PowerUpSelfTest",
	"Power On Self Test for DES3 CBC, ECB", handle_post, &des3_info);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = midbg_add_breakpoint(dbgSess, "break-insert", 
	"freebl_fips_AES_PowerUpSelfTest",
	"Power On Self Test for AES CBC,ECB", handle_aes_post, &aes_info);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = midbg_add_breakpoint(dbgSess, "break-insert", 
	"freebl_fips_SHA_PowerUpSelfTest",
	"Power On Self Test for SHA-1, SHA-224, SHA-256, SHA-384, SHA-512", 
        handle_post, &sha_info);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = midbg_add_breakpoint(dbgSess, "break-insert",
	"freebl_fips_HMAC",
	"Power On Self Test for SHA-HMAC", handle_hmac_post, &hmac_info);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = midbg_add_breakpoint(dbgSess, "break-insert",
	"freebl_fips_RSA_PowerUpSelfTest",
	"Power On Self Test for RSA", handle_post, &rsa_info);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = midbg_add_breakpoint(dbgSess, "break-insert",
	"freebl_fips_DSA_PowerUpSelfTest",
	"Power On Self Test for DSA", handle_post, &dsa_info);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = midbg_add_breakpoint(dbgSess, "break-insert",
	"freebl_fips_ECDSA_PowerUpSelfTest",
	"Power On Self Test for ECDSA", handle_post, &ecdsa_info);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    return AMVP_SUCCESS;
}
	
/* with the libraries loaded, check to make sure all the expected tests
 * have been run */
AMVP_RESULT 
verify_post(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
	    const char *async_reply, void *args)
{
    unsigned long *pflags =  (unsigned long *) args;
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_RESULT rv2 = AMVP_SUCCESS;

    midbg_log(dbgSess, "#breakpoint 1 with flags 0x%lx\n",*pflags);

    if (*pflags & FLAG_SOFTOKEN_LOADED) {
	if (*pflags & FLAG_SOFTOKEN_POST_CALLED) {
	    *pflags |= FLAG_SOFTOKEN_POST_FINISHED_LOAD;
	} else {
	    midbg_log(dbgSess,
         "# ERROR libsoftokn3.so post not called before library load\n");
	    rv = AMVP_CRYPTO_MODULE_FAIL;
	}
    } else {
	midbg_log(dbgSess,"# ERROR didn't load libsoftoken3.so\n");
	rv = AMVP_RESOURCE_FAIL;
    }
    if (*pflags & FLAG_FREEBL_LOADED) {
	if (*pflags & FLAG_FREEBL_POST_CALLED) {
	    *pflags |= FLAG_FREEBL_POST_FINISHED_LOAD;
	} else {
	    midbg_log(dbgSess,
       "# ERROR libfreeblpriv3.so post not called before library load\n");
	    rv = AMVP_CRYPTO_MODULE_FAIL;
	}
    } else {
	midbg_log(dbgSess,"# ERROR didn't load libfreeblpriv3.so\n");
	rv2 = AMVP_RESOURCE_FAIL;
    }

    if (*pflags & FLAG_DBM_LOADED) {
	if (*pflags & FLAG_DBM_POST_CALLED) {
	    *pflags |= FLAG_DBM_POST_FINISHED_LOAD;
	} else {
	    midbg_log(dbgSess,
       "# ERROR libnssdbm3.so post not called before library load\n");
	    rv = AMVP_CRYPTO_MODULE_FAIL;
	}
    } 
    /* not an error for dbm to not be loaded here. It only get's 
     * loaded if and when we need it b*/
    if (rv == AMVP_SUCCESS) {
	rv = rv2;
    }
    if (rv == AMVP_SUCCESS) {
	midbg_log(dbgSess,
         "#breakpoint 1 reached with all expected POSTs complete\n");
    }
    return rv;
}

/*
 * the dbm library gets loaded after C_Initialize time.
 */
AMVP_RESULT 
dbm_post(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
	    const char *async_reply, void *args)
{
    unsigned long *pflags =  (unsigned long *) args;

    if (*pflags & FLAG_DBM_LOADED) {
	if (*pflags & FLAG_DBM_POST_CALLED) {
	    *pflags |= FLAG_DBM_POST_FINISHED_LOAD;
	} else {
	    midbg_log(dbgSess,
         "# ERROR libnssdbm3.so post not called before library load\n");
	    return AMVP_CRYPTO_MODULE_FAIL;
	}
    } else {
	midbg_log(dbgSess,"# ERROR didn't load libnssdbm3.so\n");
	return  AMVP_RESOURCE_FAIL;
    }

    midbg_log(dbgSess,
         "#breakpoint 2 reached with all POSTs complete\n");
    return AMVP_SUCCESS;
}

/* This breakpoint forces the continuous random number test to fail.
 * We do this by coping the contents of the lastOutput buffer to our
 * current hash buffer. This forces the output to repeat the last
 * output, which is what our test is preventing */
AMVP_RESULT
drbg_force_fail2(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
	    const char *async_reply, void *args)
{
    AMVP_RESULT rv;
    unsigned long len;
    /* OK we're in SHA256_End, just before our contiuous rng test.
     * first we clear this breakpoint */
    rv = midbg_delete_breakpoint(dbgSess, breakpoint);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    /* now we do a synchonous finish */
    rv = midbg_synch_step(dbgSess, "finish", NULL);
    if (rv != AMVP_SUCCESS) {
	midbg_log(dbgSess,"# midbg_synch_finish failed\n");
	return rv;
    }

    /* found out how many bytes in our buffer */
    rv = midbg_get_scalar(dbgSess, "len", sizeof(int), &len);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    /* copy our last output to our current buffer */
    rv = midbg_copy_bytes(dbgSess, "rng->lastOutput", "thisHash", len);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }

    return AMVP_SUCCESS;
}

/* Set up to fail the continuous random number test */
AMVP_RESULT
drbg_force_fail1(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
	    const char *async_reply, void *args)
{
    AMVP_RESULT rv;
    /* OK we're in prng_HashGen, now lets got to break at memcmp  */
    rv = midbg_delete_breakpoint(dbgSess, breakpoint);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    return  midbg_add_breakpoint(dbgSess, "break-insert", "SHA256_End",
		    "continuous rng test", drbg_force_fail2, NULL);
}
    
/* insert the initial breakpoint to trip the continuous random number 
 * failure */
AMVP_RESULT
insert_drbg_failure(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
	    const char *async_reply, void *args)
{
    return  midbg_add_breakpoint(dbgSess, "break-insert", "prng_Hashgen",
		    "prng_Hashgen", drbg_force_fail1, NULL);
}

/* force the pairwise consistancy check to fail. We do this by poisoning
 * our private key exponent */
AMVP_RESULT
keypair_failure(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
	    const char *async_reply, void *args)
{
    AMVP_RESULT rv;
    unsigned char b;

    /* OK we're in RSA_NEWKey, before our pairwise consistancy check.
     * first we clear this breakpoint */
    rv = midbg_delete_breakpoint(dbgSess, breakpoint);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }

    /* now we do a synchonous finish */
    rv = midbg_synch_step(dbgSess, "finish", NULL);
    if (rv != AMVP_SUCCESS) {
	midbg_log(dbgSess,"# midbg_synch_finish failed\n");
	return rv;
    }
    /* get to the place where the optimized builds can find the variable */
    rv = midbg_synch_step(dbgSess, "step", NULL);
    if (rv != AMVP_SUCCESS) {
	midbg_log(dbgSess,"# midbg_synch_step failed\n");
	return rv;
    }
    rv = midbg_synch_step(dbgSess, "step", NULL);
    if (rv != AMVP_SUCCESS) {
	midbg_log(dbgSess,"# midbg_synch_step failed\n");
	return rv;
    }

    /* Now we poison the private key, so it no longer matches the public key */
    rv = midbg_get_bytes(dbgSess, "rsaPriv->privateExponent.data", &b, 1);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    b ^= 0x1;
    rv = midbg_put_bytes(dbgSess, "rsaPriv->privateExponent.data", &b, 1);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = midbg_get_bytes(dbgSess, "rsaPriv->exponent1.data", &b, 1);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    b ^= 0x1;
    rv = midbg_put_bytes(dbgSess, "rsaPriv->exponent1.data", &b, 1);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }

    return AMVP_SUCCESS;

}

/* insert the initial breakpoint so we can fail the pairwise 
 * consistency check */
AMVP_RESULT
insert_keypair_failure(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
	    const char *async_reply, void *args)
{
    return  midbg_add_breakpoint(dbgSess, "break-insert", "RSA_NewKey",
		    "RSA New Key", keypair_failure, NULL);
}

/* Make sure we actually called the function which checks the RSA signature
 * against the public key before return */
AMVP_RESULT 
verify_rsa_check(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
	    const char *async_reply, void *args)
{
    unsigned long *pflags =  (unsigned long *) args;

    if ((*pflags & FLAG_RSA_CHECK_CALLED) == 0) {
	    midbg_log(dbgSess,
         "# ERROR RSA Sign did not check signature agains public key\n");
	    return AMVP_CRYPTO_MODULE_FAIL;
    }

    midbg_log(dbgSess,
         "#breakpoint 8 reached with RSA signature check complete\n");
    return AMVP_SUCCESS;
}

/* clear all the old breakpoints which forces the pairwise consistancy check 
 * to fail so that we can actually generate a key pair which we need to check
 * if we are verifying the signature against the public key when we sign. */
AMVP_RESULT
clear_old_breakpoints2(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
   	const char *async_reply, void *args)
{
    static struct load_breakpoint_info rsa_check_sig_info;
    AMVP_RESULT rv;
    unsigned long *pflags = (unsigned long *)args;

    rv  = midbg_clear_all_breakpoints(dbgSess);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }

    rsa_check_sig_info.pflags = pflags;
    rsa_check_sig_info.post_entry = "RSA_PrivateKeyOpDoubleChecked";
    rsa_check_sig_info.post_label = "RSA_PrivateKeyOpDoubleChecked called";
    rsa_check_sig_info.set_flags = 0;
    rsa_check_sig_info.post_flags = FLAG_RSA_CHECK_CALLED;

    rv = midbg_add_breakpoint(dbgSess, "break-insert", "breakpoint7",
		    "breakpoint7", handle_lib_load, &rsa_check_sig_info);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    return midbg_add_breakpoint(dbgSess, "break-insert", "breakpoint8",
		    "breakpoint8", verify_rsa_check, args);
}

/* clear all the old breakpoints and insert the pairwiase consistency check */
AMVP_RESULT
clear_old_breakpoints1(midbg_session *dbgSess, midbg_breakpoint *breakpoint, 
   	const char *async_reply, void *args)
{
    AMVP_RESULT rv = midbg_clear_all_breakpoints(dbgSess);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    rv = midbg_add_breakpoint(dbgSess, "break-insert", "breakpoint5",
		    "breakpoint5", insert_keypair_failure, NULL);
    if (rv != AMVP_SUCCESS) {
	return rv;
    }
    return  midbg_add_breakpoint(dbgSess, "break-insert", "breakpoint6",
		    "breakpoint6", clear_old_breakpoints2, args);
}

/* set the breakpoints. The main breakpoints are 1) library load breakpoints,
 * and 2) breakpoint functions in our test program so we can set up targeted
 * breakpoints for the given tests */
AMVP_RESULT
pk11_debug_callback(midbg_session *dbgSession)
{
    static struct load_breakpoint_info sftk_info;
    static struct load_breakpoint_info freebl_info;
    static struct load_breakpoint_info dbm_info;
    static unsigned long flags = 0UL;
    AMVP_RESULT rc;

    sftk_info.pflags = &flags;
    sftk_info.post_entry = "sftk_startup_tests";
    sftk_info.post_label = "Softoken POST test running";
    sftk_info.set_flags = FLAG_SOFTOKEN_LOADED;
    sftk_info.post_flags = FLAG_SOFTOKEN_POST_CALLED;
    freebl_info.pflags = &flags;
    freebl_info.post_entry = "freebl_fipsPowerUpSelfTest";
    freebl_info.post_label = "Freebl POST test running";
    freebl_info.set_flags = FLAG_FREEBL_LOADED;
    freebl_info.post_flags = FLAG_FREEBL_POST_CALLED;
    dbm_info.pflags = &flags;
    dbm_info.post_entry = "lg_startup_tests";
    dbm_info.post_label = "NSS DBM POST test running";
    dbm_info.set_flags = FLAG_DBM_LOADED;
    dbm_info.post_flags = FLAG_DBM_POST_CALLED;

    /* set things up first */
    rc = midbg_add_breakpoint(dbgSession, "catch-load", "libsoftokn3.so",
		"loading libsoftokn3.so", handle_lib_load, &sftk_info);
    if (rc != AMVP_SUCCESS) { return rc; }
    rc = midbg_add_breakpoint(dbgSession, "catch-load", "libfreeblpriv3.so",
		"loading freebl", handle_lib_freebl_load, &freebl_info);
    if (rc != AMVP_SUCCESS) { return rc; }
    rc = midbg_add_breakpoint(dbgSession, "catch-load", "libnssdbm3.so",
		"loading nssdbm", handle_lib_load, &dbm_info);
    if (rc != AMVP_SUCCESS) { return rc; }
    rc = midbg_add_breakpoint(dbgSession, "break-insert", "breakpoint1",
		"breakpoint after library load", verify_post, &flags);
    if (rc != AMVP_SUCCESS) { return rc; }
    rc = midbg_add_breakpoint(dbgSession, "break-insert", "breakpoint2",
		"breakpoint after library load", dbm_post, &flags);
    if (rc != AMVP_SUCCESS) { return rc; }
    rc = midbg_add_breakpoint(dbgSession, "break-insert", "breakpoint3",
		"breakpoint before RND call", insert_drbg_failure, &flags);
    if (rc != AMVP_SUCCESS) { return rc; }
    rc = midbg_add_breakpoint(dbgSession, "break-insert", "breakpoint4",
	"breakpoint after module close", clear_old_breakpoints1, &flags);
    if (rc != AMVP_SUCCESS) { return rc; }
    /* breakpoint 5 is set after we hit breakpoint 4, which clears all our old
     * unused breakpoints */
    return AMVP_SUCCESS;
}



AMVP_RESULT 
self_test_verify(AMVP_TEST_CASE *tc)
{
   return amvp_not_implemented(tc);
}


/*
 * Free up all the output logs from the test
 */
void 
output_log_cleanup(AMVP_TEST_CASE *tc)
{
    int i;
    for (i=0; i < tc->log_count; i++) {
	free((char *)tc->log[i]);
	tc->log[i] = 0;
    }
}

static char *pk11_mode_log = NULL;
static AMVP_RESULT pk11_mode_status = -1;
static char *pk11_debug_log = NULL;
static AMVP_RESULT pk11_debug_status = -1;

/* run pk11 mode. This code runs the test once and includes the log in 
 * the first test. All other tests get a reference to that log 
 * pk11mode is the test case that comes with NSS upstream and tests all
 * of the TE functions that can be tested without using a debugger or an
 * external programs.
 */
AMVP_RESULT pk11_mode(AMVP_TEST_CASE *tc, char *const argv[], const char *info)
{
   char *out_log;
   AMVP_RESULT rv, status;
 
   if (pk11_mode_status == -1) {
   	out_log = amvpu_exec_log("nss", PK11MODE, argv, &status);
	pk11_mode_status = status;
	pk11_mode_log = NULL;
	if (out_log) {
	    char buf[256];
	    snprintf(buf, sizeof(buf),"See log for test %s\n",tc->test_name);
	    pk11_mode_log = strdup(buf);
	}
   } else {
	status = pk11_mode_status;
	out_log = pk11_mode_log ? strdup(pk11_mode_log): NULL;
   }
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


/*
 * Debug tests are test the require a debugger to run the tests. The debuggger
 * is controlled by the breakpoint functions in the file (above). 
 * amvpu_exec_debug() is similiar to amvpu_exec except it runs the program
 * under the debugger, and creates a debug context, then calls  the callback
 * function before the program is started to set up break points and watch
 * points. The last parameter tells which kinds of output to filter out from
 * the returned log */
AMVP_RESULT 
debug_tests(AMVP_TEST_CASE *tc, char *info)
{
   char *out_log;
   AMVP_RESULT rv, status;
   char *debug_argv[] = {"pk11debug", 0 };

   if (pk11_debug_status == -1) {
   	out_log = amvpu_exec_debug("nss", "pk11debug",debug_argv,&status, 
			pk11_debug_callback, DBG_INFO_FLAG|DBG_PROMPT_FLAG);
	pk11_debug_status = status;
	pk11_debug_log = NULL;
	if (out_log) {
	    char buf[256];
	    snprintf(buf, sizeof(buf),"See log for test %s\n",tc->test_name);
	    pk11_debug_log = strdup(buf);
	}
   } else {
	status = pk11_debug_status;
	out_log = pk11_debug_log ? strdup(pk11_debug_log): NULL;
   }
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


/*
 * This handles each test case, it runs the test for the test case, returns
 * the result and the log file for the test case as well and information
 * to interpret the results from the test case */
AMVP_RESULT amvp_handle_test(AMVP_CTX *ctx, AMVP_TEST_CASE *tc)
{
   char *FV_argv[] = { PK11MODE, "-F","-v", 0 };

   switch (tc->test_type) {
   case AMVP_TE01_03_02:
	return pk11_mode(tc, FV_argv, 
"pk11mode invokes softokn FIPS mode in 'FIPS MODE'.\n"
"Look for:\"Loaded FC_GetFunctionList for FIPS MODE\"\n"
"and\n"
"\"CInitialize succeeded\"\n"
"in the log");
   case AMVP_TE01_04_02:
	return pk11_mode(tc, FV_argv, 
"pk11mode invokes softokn FIPS mode in 'FIPS MODE'.\n"
"Look for:\"Loaded FC_GetFunctionList for FIPS MODE\"\n"
"and\n"
"\"CInitialize succeeded\"\n"
"in the log");
   case AMVP_TE02_06_02:
	return pk11_mode(tc, FV_argv, 
"pk11mode checks error state in PKM_ErrorState, making sure all function\n"
"not explicitly called out in the security policy section 2.1 as operating\n"
"in error state, fails with CRK_DEVICE_ERROR when in error state\n");
   case AMVP_TE02_06_04:
	return amvp_does_not_apply(tc,
"NSS runs selt-tests at library load time, no functions can be called until\n"
"the library load is complete. (Section 2.2 of the security policy)");
   case AMVP_TE02_13_03:
	return amvp_does_not_apply(tc, "Hardware only");
   case AMVP_TE02_14_02:
	return pk11_mode(tc, FV_argv, 
"NSS never outputs CPSs. pk11mode verifies this in PKM_KeyTests,\n"
" which tries to read generated keys. see:\n"
"\"C_GetAttributeValue correctly blocked attempt to read \n\" lines in the log");
   case AMVP_TE03_02_02:
	return pk11_mode(tc, FV_argv, 
"NSS has only one operator.\n"
"In pk11mode,  PKM_KeyTests verifies that keys can not be created if \n"
"the operator is not logged see\n"
"\"C_GenerateKey returned as EXPECTED with 0x00000101, CKR_USER_NOT_LOGGED_IN\n""since not logged in\"\n"
"and \n"
"\"C_GenerateKeyPair returned as EXPECTED with 0x00000101, CKR_USER_NOT_LOGGED_IN\n"
"since not logged in\n\"");
   case AMVP_TE03_11_02:
	return pk11_mode(tc, FV_argv, 
"Show Status indicator is the return codes from the various functions.\n"
"pk11mode test these return codes, included error indication \n"
" (CKR_DEVICE_ERROR) and Login status CKR_USER_NOT_LOGGED_IN\n");
   case AMVP_TE03_11_03:
	return debug_tests(tc,
"Debug tests sets a breakpoint at the self tests and makes sure they are\n"
"called at library load time\n");
   case AMVP_TE03_03_02:
	return amvp_does_not_apply(tc, "NSS does not support bypass");
   case AMVP_TE03_14_02:
   case AMVP_TE03_15_02:
	return pk11_mode(tc, FV_argv, 
"NSS has two roles, Crypto officer and user. pk11mode tests\n"
"Crypto officer login when Initing database pasword:"
" user logged in for other access");
   case AMVP_TE03_17_02:
	return pk11_mode(tc, FV_argv, 
"PKM_SessionLogin verifies the incorrect login case.\n");
   case AMVP_TE03_18_02:
	return pk11_mode(tc, FV_argv, 
"NSS has two roles, Crypto officer and user. pk11mode tests\n"
"Crypto officer login when Initing database pasword:"
" user logged in for other access");
   case AMVP_TE03_21_02:
	return amvp_does_not_apply(tc, "Hardware only");
   case AMVP_TE03_22_02:
	 /* create a database with a password */
	 /* change the database password */
	 /* access the database with old password, expect failure */
	 return pk11_mode(tc, FV_argv,
"PKM_InitPWforDB initializes the database with one password, changes that\n"
"password, then tries to use the old password to change the password again.\n"
"The second C_SetPin fails\n"); 
   case AMVP_TE03_23_02:
	return pk11_mode(tc, FV_argv, 
"PKM_InitPWforDB tries to log in before the token is initialized\n");
   case AMVP_TE03_24_02:
	return pk11_mode(tc, FV_argv,
"NSS has two roles, Crypto officer and user. pk11mode tests\n"
"Crypto officer login when Initing database pasword:"
" user logged in for other access");
   case AMVP_TE04_03_01:
	/* testing error states */
	return pk11_mode(tc,FV_argv,
"pk11mode checks error state in PKM_ErrorState, making sure all function\n"
"not explicitly called out in the security policy section 2.1 as operating\n"
"in error state, fails with CRK_DEVICE_ERROR when in error state\n");
   case AMVP_TE04_05_08:
	return pk11_mode(tc, FV_argv, 
"pk11mode tests all NSS states as follows:\n"
" Loading the library takes the Module from Power off (1.x) to Power Up Self\n"
"   Test (1.B)\n"
" Power Up Self Test (1.B) proceeds to Inactive (1.A) on success of those tests\n"
" C_Initialize takes the Module from Inactive (1.A) to Public\n"
"  Services (1.C)\n"
" C_Login takes the Module from Public Services (1.C) to NSS User\n"
"  Services (2)\n"
" C_Logout takes the Module from NSS User Services(2) back to Public\n"
"  Services (1.C)\n"
" PKM_ErrorState takes the Module from Public Services (1.C) to \n"
"  NSS User Services (2) then to Error (3.A)\n"
" C_Finalize takes to module from either Public Services (1.C) or Error (3.A)\n"
"  to Inactive(1.A)\n"
" PKM_HybridMode takes the token from Inactive (1.A) to Non-Fips Mode (5.B)\n"
"  and back.\n"
" Unload Library takes the module from any state back to Power off (1.x)\n"
" PKM_Mangle tries to load a modified library, this takes the library from\n"
"  Power off (1.x) to Inactive Error (3.B).");
   case AMVP_TE07_01_02:
	return pk11_mode(tc, FV_argv,
"PKM_CSPTests creates a key of a known value and verifies that the key not\n"
"not left on the stack or in the heap after various operations\n"
"It also verfies that plain text passed to encrypt is not left in a buffer\n"
"after the encrypt operation");
   case AMVP_TE07_02_02:
	return amvp_does_not_apply(tc, 
			"NSS does store implicitly trusted public keys");
   case AMVP_TE07_15_02:
   case AMVP_TE07_15_03:
   case AMVP_TE07_15_04:
	return amvp_does_not_apply(tc, 
			"NSS does not provide intermediate key output");
   case AMVP_TE07_23_03:
	return amvp_does_not_apply(tc, "NSS does not provide use seed keys");
   case AMVP_TE07_25_02:
	return amvp_does_not_apply(tc, "NSS only supports one entity");
   case AMVP_TE07_27_02:
   case AMVP_TE07_29_02:
   case AMVP_TE07_32_02:
	return amvp_does_not_apply(tc, 
			"NSS does not support an external display device");
   case AMVP_TE07_39_02:
	return pk11_mode(tc, FV_argv, 
		"Crypto officer login for Initing database pasword,"
		" user logged in for other access");
   case AMVP_TE07_41_02:
	return pk11_mode(tc, FV_argv,
"PKM_CSPTests creates a key of a known value and verifies that the key not\n"
"not left on the stack or in the heap after various operations\n"
"It also verfies that plain text passed to encrypt is not left in a buffer\n"
"after the encrypt operation");
   case AMVP_TE09_04_03:
	return debug_tests(tc,
"Debug tests sets a breakpoint at the self tests and makes sure they are\n"
"called at library load time\n");
   case AMVP_TE09_05_03:
	return pk11_mode(tc, FV_argv, 
"pk11mode checks error state in PKM_ErrorState, making sure all function\n"
"not explicitly called out in the security policy section 2.1 as operating\n"
"in error state, fails with CRK_DEVICE_ERROR when in error state\n");
   case AMVP_TE09_06_02:
	return debug_tests(tc,
"Debug tests sets a breakpoint at the continuous random number test and\n"
"forces an error and verifies that the output is disabled\n");
   case AMVP_TE09_07_03:
	return debug_tests(tc,
"Debug tests creates an error in the continuous random number tests and\n"
"then resets the token and does a login operation \n");
   case AMVP_TE09_09_02:
	return debug_tests(tc,
"Debug tests sets a breakpoint at the self tests and makes sure they are\n"
"called at library load time without additional call.\n");
   case AMVP_TE09_10_02:
	return pk11_mode(tc, FV_argv, 
"pk11mode calls C_Initialize at power startup. The return code from\n"
"C_Initialize tells you if there was a powerup error\n");
   case AMVP_TE09_12_02:
	return debug_tests(tc,
"Debug tests sets a breakpoint at the self tests and makes sure they are\n"
"called at library load time without additional call.\n");
   case AMVP_TE09_16_01:
   case AMVP_TE09_16_02:
	return debug_tests(tc,
"Debug tests sets a breakpoint at each algorithm self test and logs\n"
"that the self-test has been run.\n");
   case AMVP_TE09_19_03:
	return debug_tests(tc,
"Debug tests sets a breakpoint at each algorithm self test and logs\n"
"that the self-test has been run. Code inspection shows each algorithm\n"
"has it's own known answer test\n");
   case AMVP_TE09_22_07:
	return pk11_mode(tc, FV_argv, 
"pk11mode tries to load a mangled version of the module and shows that\n"
"Fips mode can't initialize \n");
   case AMVP_TE09_24_01:
	return amvp_does_not_apply(tc, "NSS does not support EDC");
   case AMVP_TE09_27_01:
   case AMVP_TE09_27_02:
	return amvp_does_not_apply(tc, "NSS does not support critical functions");
   case AMVP_TE09_31_01:
   case AMVP_TE09_33_01:
	return debug_tests(tc,
"pk11debug verifies that the pairwise consistency check is completed\n"
"by poisoning the private exponent after generation and verifying that\n"
"key gen fails.\n\n"
"- keys usable for signatures (DSA, ECDSA and RSA): the consistency of the\n"
"keys are tested by the calculation and verification of the signature.\n\n"
"- keys usable for encryption (RSA): the consistency of the keys are tested\n"
"by verification that ciphertext is different from plaintext after\n"
"encryption, and that new plaintext matches the original plaintext after\n"
"decryption against the public key before returning it.\n");
   case AMVP_TE09_35_04:
   case AMVP_TE09_35_05:
	return debug_tests(tc,
"pk11debug tries to load a mangled version of each dependent library ot the\n"
"the module, then execs a simple test program that tries to initialize FIPS \n"
"FIPS mode. It will fail if any of the libraries are mangled, and succeed\n"
"when all the libraries are prestine\n");
   default:
	break;
   }
   return amvp_not_implemented(tc);
}
