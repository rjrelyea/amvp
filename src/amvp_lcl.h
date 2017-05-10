/*****************************************************************************
* Copyright (c) 2016, Cisco Systems, Inc.
* All rights reserved.

* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
#ifndef amvp_lcl_h
#define amvp_lcl_h

#include "parson.h"

#define AMVP_VERSION    "0.3"

#define AMVP_ALG_MAX 34  /* Used by alg_tbl[] */

#define AVMP_TEST_TE01_03_02 "TE01.03.02"
#define AVMP_TEST_TE01_04_02 "TE01.04.02"
#define AVMP_TEST_TE02_06_02 "TE02.06.02"
#define AVMP_TEST_TE02_06_04 "TE02.06.04"
#define AVMP_TEST_TE02_13_03 "TE02.13.03"
#define AVMP_TEST_TE02_14_02 "TE02.14.02"
#define AVMP_TEST_TE03_02_02 "TE03.02.02"
#define AVMP_TEST_TE03_11_02 "TE03.11.02"
#define AVMP_TEST_TE03_11_03 "TE03.11.03"
#define AVMP_TEST_TE03_03_02 "TE03.03.02"
#define AVMP_TEST_TE03_14_02 "TE03.14.02"
#define AVMP_TEST_TE03_15_02 "TE03.15.02"
#define AVMP_TEST_TE03_17_02 "TE03.17.02"
#define AVMP_TEST_TE03_18_02 "TE03.18.02"
#define AVMP_TEST_TE03_21_02 "TE03.21.02"
#define AVMP_TEST_TE03_22_02 "TE03.22.02"
#define AVMP_TEST_TE03_23_02 "TE03.23.02"
#define AVMP_TEST_TE03_24_02 "TE03.24.02"
#define AVMP_TEST_TE04_03_01 "TE04.03.01"
#define AMVP_TEST_TE04_05_08 "TE04.05.08"
#define AMVP_TEST_TE07_01_02 "TE07.01.02"
#define AMVP_TEST_TE07_02_02 "TE07.02.02"
#define AMVP_TEST_TE07_15_02 "TE07.15.02"
#define AMVP_TEST_TE07_15_03 "TE07.15.03"
#define AMVP_TEST_TE07_15_04 "TE07.15.04"
#define AMVP_TEST_TE07_23_03 "TE07.23.03"
#define AMVP_TEST_TE07_25_02 "TE07.25.02"
#define AMVP_TEST_TE07_27_02 "TE07.27.02"
#define AMVP_TEST_TE07_29_02 "TE07.29.02"
#define AMVP_TEST_TE07_32_02 "TE07.32.02"
#define AMVP_TEST_TE07_39_02 "TE07.39.02"
#define AMVP_TEST_TE07_41_02 "TE07.41.02"
#define AMVP_TEST_TE09_04_03 "TE09.04.03"
#define AMVP_TEST_TE09_05_03 "TE09.05.03"
#define AMVP_TEST_TE09_06_02 "TE09.06.02"
#define AMVP_TEST_TE09_07_03 "TE09.07.03"
#define AMVP_TEST_TE09_09_02 "TE09.09.02"
#define AMVP_TEST_TE09_10_02 "TE09.10.02"
#define AMVP_TEST_TE09_12_02 "TE09.12.02"
#define AMVP_TEST_TE09_16_01 "TE09.16.01"
#define AMVP_TEST_TE09_16_02 "TE09.16.02"
#define AMVP_TEST_TE09_19_03 "TE09.19.03"
#define AMVP_TEST_TE09_22_07 "TE09.22.07"
#define AMVP_TEST_TE09_24_01 "TE09.24.01"
#define AMVP_TEST_TE09_27_01 "TE09.27.01"
#define AMVP_TEST_TE09_27_02 "TE09.27.02"
#define AMVP_TEST_TE09_31_01 "TE09.31.01"
#define AMVP_TEST_TE09_35_04 "TE09.35.04"
#define AMVP_TEST_TE09_35_05 "TE09.35.05"



#define AMVP_LOG_BUF_MAX        1024*1024
#define AMVP_REG_BUF_MAX        1024*65
#define AMVP_RETRY_TIME_MAX         60 /* seconds */
#define AMVP_JWT_TOKEN_MAX      1024

#define AMVP_PATH_SEGMENT_DEFAULT ""


typedef struct amvp_alg_handler_t AMVP_ALG_HANDLER;

struct amvp_alg_handler_t {
    AMVP_TEST            testr;
    AMVP_RESULT (*handler)(AMVP_CTX *ctx, JSON_Object *obj);
    char		   *name;
};

typedef struct amvp_vs_list_t {
    int vs_id;
    struct amvp_vs_list_t   *next;
} ACMP_VS_LIST;

/*
 * Supported length list
 */
typedef struct amvp_sl_list_t {
    int length;
    struct amvp_sl_list_t *next;
} AMVP_SL_LIST;

#ifdef notdef
typedef struct amvp_sym_cipher_capability {
    AMVP_SYM_CIPH_DIR direction;
    AMVP_SYM_CIPH_KO keying_option;
    AMVP_SYM_CIPH_IVGEN_SRC ivgen_source;
    AMVP_SYM_CIPH_IVGEN_MODE ivgen_mode;
    AMVP_SL_LIST *keylen;
    AMVP_SL_LIST *ptlen;
    AMVP_SL_LIST *ivlen;
    AMVP_SL_LIST *aadlen;
    AMVP_SL_LIST *taglen;
} AMVP_SYM_CIPHER_CAP;

typedef struct amvp_hash_capability {
    int               in_bit;
    int               in_empty;
} AMVP_HASH_CAP;

typedef struct amvp_drbg_prereq_alg_val {
    AMVP_DRBG_PRE_REQ alg;
    char *val;
} AMVP_DRBG_PREREQ_ALG_VAL;

typedef struct amvp_drbg_prereq_vals {
    AMVP_DRBG_PREREQ_ALG_VAL prereq_alg_val;
    struct amvp_drbg_prereq_vals *next;
} AMVP_DRBG_PREREQ_VALS;

typedef struct amvp_drbg_cap_mode {
    AMVP_DRBG_MODE   mode;                   //"3KeyTDEA",
    int              der_func_enabled;       //":"yes",
    AMVP_DRBG_PREREQ_VALS *prereq_vals;
    int              pred_resist_enabled;    //": "yes",
    int              reseed_implemented;     //" : "yes",
    int              entropy_input_len;      //":"112",
    int              entropy_len_max;
    int              entropy_len_min;
    int              entropy_len_step;
    int              nonce_len;              //":"56",
    int              nonce_len_max;
    int              nonce_len_min;
    int              nonce_len_step;
    int              perso_string_len;       //":"0",
    int              perso_len_max;
    int              perso_len_min;
    int              perso_len_step;
    int              additional_input_len;   //":"0",
    int              additional_in_len_max;
    int              additional_in_len_min;
    int              additional_in_len_step;
    int              returned_bits_len;      //":"256"
} AMVP_DRBG_CAP_MODE;

typedef struct amvp_cap_mode_list_t {
    AMVP_DRBG_CAP_MODE cap_mode;
    struct amvp_cap_mode_list_t *next;
} AMVP_DRBG_CAP_MODE_LIST;

typedef struct amvp_drbg_capability {
    AMVP_CIPHER             cipher;
    AMVP_DRBG_CAP_MODE_LIST *drbg_cap_mode_list;
} AMVP_DRBG_CAP;

struct amvp_drbg_mode_name_t {
    AMVP_DRBG_MODE  mode;
    char           *name;
};

typedef struct amvp_caps_list_t {
    AMVP_CIPHER       cipher;
    AMVP_CAP_TYPE     cap_type;
    union {
	AMVP_SYM_CIPHER_CAP *sym_cap;
    AMVP_HASH_CAP       *hash_cap;
    AMVP_DRBG_CAP       *drbg_cap;
	//TODO: add other cipher types: asymmetric, DRBG, hash, etc.
    } cap;
    AMVP_RESULT (*crypto_handler)(AMVP_TEST_CASE *test_case);
    struct amvp_caps_list_t *next;
} AMVP_CAPS_LIST;

#endif

/*
 * This struct holds all the global data for a test session, such
 * as the server name, port#, etc.  Some of the values in this
 * struct are transitory and used during the JSON parsing and
 * vector processing logic.
 */
struct amvp_ctx_t {
    /* Global config values for the session */
    char        *server_name;
    char        *path_segment;
    int server_port;
    char        *cacerts_file; /* Location of CA certificates Curl will use to verify peer */
    int verify_peer;           /* enables TLS peer verification via Curl */
    char        *tls_cert;     /* Location of PEM encoded X509 cert to use for TLS client auth */
    char        *tls_key;      /* Location of PEM encoded priv key to use for TLS client auth */
    char	*vendor_name;
    char	*vendor_url;
    char	*contact_name;
    char	*contact_email;
    char	*module_name;
    char	*module_type;
    char	*module_version;
    char	*module_desc;

    /* test session data */
    AMVP_VS_LIST    *vs_list;
    char            *jwt_token; /* access_token provided by server for authenticating REST calls */

    /* crypto module capabilities list */
    /* AMVP_CAPS_LIST  *caps_list; */

    /* application callbacks */
    AMVP_RESULT (*test_progress_cb)(char *msg);

    /* Transitory values */
    char        *reg_buf;    /* holds the JSON registration response */
    char        *kat_buf;    /* holds the current set of vectors being processed */
    char        *upld_buf;   /* holds the HTTP response from server when uploading results */
    JSON_Value      *kat_resp;   /* holds the current set of vector responses */
    int read_ctr;            /* used during curl processing */
    int vs_id;               /* vs_id currently being processed */
};

AMVP_RESULT amvp_send_register(AMVP_CTX *ctx, char *reg);
AMVP_RESULT amvp_retrieve_vector_set(AMVP_CTX *ctx, int vs_id);
AMVP_RESULT amvp_retrieve_vector_set_result(AMVP_CTX *ctx, int vs_id);
AMVP_RESULT amvp_submit_vector_responses(AMVP_CTX *ctx);
void amvp_log_msg (AMVP_CTX *ctx, const char *format, ...);
AMVP_RESULT amvp_hexstr_to_bin(const unsigned char *src, unsigned char *dest, int dest_max);
AMVP_RESULT amvp_bin_to_hexstr(const unsigned char *src, unsigned int src_len, unsigned char *dest);

/*
 * These are the handler routines for each KAT operation
 */
AMVP_RESULT amvp_module_test_handler(AMVP_CTX *ctx, JSON_Object *obj);

/*
 * AMVP utility functions used internally
 */
#ifdef notdef
AMVP_CAPS_LIST* amvp_locate_cap_entry(AMVP_CTX *ctx, AMVP_CIPHER cipher);
char * amvp_lookup_cipher_name(AMVP_CIPHER alg);
#endif
AMVP_TEST amvp_lookup_module_test_index(const char *module_test);
unsigned int yes_or_no(AMVP_CTX *ctx, const char *text);
AMVP_RESULT amvp_create_array (JSON_Object **obj, JSON_Value **val, JSON_Array **arry);
#endif
