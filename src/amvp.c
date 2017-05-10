/** @file */
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "amvp.h"
#include "amvp_lcl.h"
#include "parson.h"

/*
 * Forward prototypes for local functions
 */
static AMVP_RESULT amvp_parse_register(AMVP_CTX *ctx);
static AMVP_RESULT amvp_process_vsid(AMVP_CTX *ctx, int vs_id);
static AMVP_RESULT amvp_process_vector_set(AMVP_CTX *ctx, JSON_Object *obj);
static AMVP_RESULT amvp_dispatch_vector_set(AMVP_CTX *ctx, JSON_Object *obj);
static AMVP_RESULT amvp_set_test_handler(
    AMVP_CTX *ctx,
    AMVP_TEST test_type,
    AMVP_RESULT (*test_handler)(AMVP_TEST_CASE *test_case));
static void amvp_cap_free_sl(AMVP_SL_LIST *list);
static AMVP_RESULT amvp_get_result_vsid(AMVP_CTX *ctx, int vs_id);


/*
 * This table maps AMVP operations to handlers within libamvp.
 * Each AMVP operation may have unique parameters.  For instance,
 * the parameters to test RSA are different than AES.  Therefore,
 * we allow for a unique handler to be registered for each
 * AMVP operation.
 *
 * WARNING:
 * This table is not sparse, it must contain AMVP_OP_MAX entries.
 */
AMVP_TEST_HANDLER alg_tbl[AMVP_ALG_MAX] = {
    {AMVP_TE01_03_02,	TE01_03_02amvp_test_handler,	AMVP_TEST_TE01_03_02},
    {AMVP_TE01_04_02,	TE01_04_02amvp_test_handler,	AMVP_TEST_TE01_04_02},
    {AMVP_TE02_06_02,	TE02_06_02amvp_test_handler,	AMVP_TEST_TE02_06_02},
    {AMVP_TE02_06_04,	TE02_06_04amvp_test_handler,	AMVP_TEST_TE02_06_04},
    {AMVP_TE02_13_03,	TE02_13_03amvp_test_handler,	AMVP_TEST_TE02_13_03},
    {AMVP_TE02_14_02,	TE02_14_02amvp_test_handler,	AMVP_TEST_TE02_14_02},
    {AMVP_TE03_02_02,	TE03_02_02amvp_test_handler,	AMVP_TEST_TE03_02_02},
    {AMVP_TE03_11_02,	TE03_11_02amvp_test_handler,	AMVP_TEST_TE03_11_02},
    {AMVP_TE03_11_03,	TE03_11_03amvp_test_handler,	AMVP_TEST_TE03_11_03},
    {AMVP_TE03_03_02,	TE03_03_02amvp_test_handler,	AMVP_TEST_TE03_03_02},
    {AMVP_TE03_14_02,	TE03_14_02amvp_test_handler,	AMVP_TEST_TE03_14_02},
    {AMVP_TE03_15_02,	TE03_15_02amvp_test_handler,	AMVP_TEST_TE03_15_02},
    {AMVP_TE03_17_02,	TE03_17_02amvp_test_handler,	AMVP_TEST_TE03_17_02},
    {AMVP_TE03_18_02,	TE03_18_02amvp_test_handler,	AMVP_TEST_TE03_18_02},
    {AMVP_TE03_21_02,	TE03_21_02amvp_test_handler,	AMVP_TEST_TE03_21_02},
    {AMVP_TE03_22_02,	TE03_22_02amvp_test_handler,	AMVP_TEST_TE03_22_02},
    {AMVP_TE03_23_02,	TE03_23_02amvp_test_handler,	AMVP_TEST_TE03_23_02},
    {AMVP_TE03_24_02,	TE03_24_02amvp_test_handler,	AMVP_TEST_TE03_24_02},
    {AMVP_TE04_03_01,	TE04_03_01amvp_test_handler,	AMVP_TEST_TE04_03_01},
    {AMVP_TE04_05_08,	TE04_05_08amvp_test_handler,	AMVP_TEST_TE04_05_08},
    {AMVP_TE07_01_02,	TE07_01_02amvp_test_handler,	AMVP_TEST_TE07_01_02},
    {AMVP_TE07_02_02,	TE07_02_02amvp_test_handler,	AMVP_TEST_TE07_02_02},
    {AMVP_TE07_15_02,	TE07_15_02amvp_test_handler,	AMVP_TEST_TE07_15_02},
    {AMVP_TE07_15_03,	TE07_15_03amvp_test_handler,	AMVP_TEST_TE07_15_03},
    {AMVP_TE07_15_04,	TE07_15_04amvp_test_handler,	AMVP_TEST_TE07_15_04},
    {AMVP_TE07_23_03,	TE07_23_03amvp_test_handler,	AMVP_TEST_TE07_23_03},
    {AMVP_TE07_25_02,	TE07_25_02amvp_test_handler,	AMVP_TEST_TE07_25_02},
    {AMVP_TE07_27_02,	TE07_27_02amvp_test_handler,	AMVP_TEST_TE07_27_02},
    {AMVP_TE07_29_02,	TE07_29_02amvp_test_handler,	AMVP_TEST_TE07_29_02},
    {AMVP_TE07_32_02,	TE07_32_02amvp_test_handler,	AMVP_TEST_TE07_32_02},
    {AMVP_TE07_39_02,	TE07_39_02amvp_test_handler,	AMVP_TEST_TE07_39_02},
    {AMVP_TE07_41_02,	TE07_41_02amvp_test_handler,	AMVP_TEST_TE07_41_02},
    {AMVP_TE09_04_03,	TE09_04_03amvp_test_handler,	AMVP_TEST_TE09_04_03},
    {AMVP_TE09_05_03,	TE09_05_03amvp_test_handler,	AMVP_TEST_TE09_05_03},
    {AMVP_TE09_06_02,	TE09_06_02amvp_test_handler,	AMVP_TEST_TE09_06_02},
    {AMVP_TE09_07_03,	TE09_07_03amvp_test_handler,	AMVP_TEST_TE09_07_03},
    {AMVP_TE09_09_02,	TE09_09_02amvp_test_handler,	AMVP_TEST_TE09_09_02},
    {AMVP_TE09_10_02,	TE09_10_02amvp_test_handler,	AMVP_TEST_TE09_10_02},
    {AMVP_TE09_12_02,	TE09_12_02amvp_test_handler,	AMVP_TEST_TE09_12_02},
    {AMVP_TE09_16_01,	TE09_16_01amvp_test_handler,	AMVP_TEST_TE09_16_01},
    {AMVP_TE09_16_02,	TE09_16_02amvp_test_handler,	AMVP_TEST_TE09_16_02},
    {AMVP_TE09_19_03,	TE09_19_03amvp_test_handler,	AMVP_TEST_TE09_19_03},
    {AMVP_TE09_22_07,	TE09_22_07amvp_test_handler,	AMVP_TEST_TE09_22_07},
    {AMVP_TE09_24_01,	TE09_24_01amvp_test_handler,	AMVP_TEST_TE09_24_01},
    {AMVP_TE09_27_01,	TE09_27_01amvp_test_handler,	AMVP_TEST_TE09_27_01},
    {AMVP_TE09_27_02,	TE09_27_02amvp_test_handler,	AMVP_TEST_TE09_27_02},
    {AMVP_TE09_31_01,	TE09_31_01amvp_test_handler,	AMVP_TEST_TE09_31_01},
    {AMVP_TE09_35_04,	TE09_35_04amvp_test_handler,	AMVP_TEST_TE09_35_04},
    {AMVP_TE09_35_05,	TE09_35_05amvp_test_handler,	AMVP_TEST_TE09_35_05}
};



/*
 * This is the first function the user should invoke to allocate
 * a new context to be used for the test session.
 */
AMVP_RESULT amvp_create_test_session(AMVP_CTX **ctx,
                                     AMVP_RESULT (*progress_cb)(char *msg))
{
    *ctx = calloc(1, sizeof(AMVP_CTX));
    if (!*ctx) {
        return AMVP_MALLOC_FAIL;
    }
    (*ctx)->path_segment = strdup(AMVP_PATH_SEGMENT_DEFAULT);

    if (progress_cb) {
        (*ctx)->test_progress_cb = progress_cb;
    }

    return AMVP_SUCCESS;
}


/*
 * The application will invoke this to free the AMVP context
 * when the test session is finished.
 */
AMVP_RESULT amvp_free_test_session(AMVP_CTX *ctx)
{
    AMVP_VS_LIST *vs_entry, *vs_e2;
    AMVP_CAPS_LIST *cap_entry, *cap_e2;

    if (ctx) {
        if (ctx->reg_buf) free(ctx->reg_buf);
        if (ctx->kat_buf) free(ctx->kat_buf);
        if (ctx->upld_buf) free(ctx->upld_buf);
        if (ctx->kat_resp) json_value_free(ctx->kat_resp);
        if (ctx->server_name) free(ctx->server_name);
        if (ctx->vendor_name) free(ctx->vendor_name);
        if (ctx->vendor_url) free(ctx->vendor_url);
        if (ctx->contact_name) free(ctx->contact_name);
        if (ctx->contact_email) free(ctx->contact_email);
        if (ctx->module_name) free(ctx->module_name);
        if (ctx->module_version) free(ctx->module_version);
        if (ctx->module_type) free(ctx->module_type);
        if (ctx->module_desc) free(ctx->module_desc);
        if (ctx->path_segment) free(ctx->path_segment);
        if (ctx->cacerts_file) free(ctx->cacerts_file);
        if (ctx->tls_cert) free(ctx->tls_cert);
        if (ctx->tls_key) free(ctx->tls_key);
        if (ctx->vs_list) {
            vs_entry = ctx->vs_list;
            while (vs_entry) {
                vs_e2 = vs_entry->next;
                free(vs_entry);
                vs_entry = vs_e2;
            }
        }
        if (ctx->caps_list) {
            cap_entry = ctx->caps_list;
            while (cap_entry) {
                cap_e2 = cap_entry->next;
                switch (cap_entry->cap_type) {
                        case AMVP_SYM_TYPE:
                            free(cap_entry->cap.sym_cap);
                            amvp_cap_free_sl(cap_entry->cap.sym_cap->keylen);
                            amvp_cap_free_sl(cap_entry->cap.sym_cap->ptlen);
                            amvp_cap_free_sl(cap_entry->cap.sym_cap->ivlen);
                            amvp_cap_free_sl(cap_entry->cap.sym_cap->aadlen);
                            amvp_cap_free_sl(cap_entry->cap.sym_cap->taglen);
                            free(cap_entry);
                            cap_entry = cap_e2;
                            break;
                        case AMVP_HASH_TYPE:
                            break;
                        case AMVP_DRBG_TYPE:
                            cap_e2 = cap_entry->next;
                            amvp_free_drgb_struct(cap_entry);
                            free(cap_entry);
                            cap_entry = cap_e2;
                            break;
                        default:
                            break;
                }
            }
        }
        if (ctx->jwt_token) free(ctx->jwt_token);
        free(ctx);
    }
    return AMVP_SUCCESS;
}

/*
 * Adds the length provided to the linked list of
 * supported lengths.
 */
static AMVP_RESULT amvp_cap_add_length(AMVP_SL_LIST **list, int len)
{
    AMVP_SL_LIST *l = *list;
    AMVP_SL_LIST *new;

    /*
     * Allocate some space for the new entry
     */
    new = calloc(1, sizeof(AMVP_SL_LIST));
    if (!new) {
	return AMVP_MALLOC_FAIL;
    }
    new->length = len;

    /*
     * See if we need to create the list first
     */
    if (!l) {
	*list = new;
    } else {
	/*
	 * Find the end of the list and add the new entry there
	 */
	while (l->next) {
	    l = l->next;
	}
	l->next = new;
    }
    return AMVP_SUCCESS;
}

/*
 * Simple utility function to free a supported length
 * list from the capabilities structure.
 */
static void amvp_cap_free_sl(AMVP_SL_LIST *list)
{
    AMVP_SL_LIST *top = list;
    AMVP_SL_LIST *tmp;

    while(top) {
	tmp = top;
	top = top->next;
	free(tmp);
    }
}

/*
 * This function is called by the application to register a crypto
 * capability for symmetric ciphers, along with a handler that the
 * application implements when that particular crypto operation is
 * needed by libamvp.
 *
 * This function should be called one or more times for each crypto
 * capability supported by the crypto module being validated.  This
 * needs to be called after amvp_create_test_session() and prior to
 * calling amvp_register().
 *
 */
AMVP_RESULT amvp_set_test_handler(
	AMVP_CTX *ctx,
        AMVP_RESULT (*test_handler)(AMVP_TEST_CASE *test_case))
{
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        return AMVP_INVALID_ARG;
    }

    cap = calloc(1, sizeof(AMVP_SYM_CIPHER_CAP));
    if (!cap) {
	return AMVP_MALLOC_FAIL;
    }

    //TODO: need to validate that cipher, mode, etc. are valid values
    //      we also need to make sure we're not adding a duplicate
    cap->direction = dir;
    cap->keying_option = keying_option;
    cap->ivgen_source = ivgen_source;
    cap->ivgen_mode = ivgen_mode;

    return (amvp_append_sym_cipher_caps_entry(ctx, cap, cipher, crypto_handler));
}

/*
 * Allows application to specify the vendor attributes for
 * the test session.
 */
AMVP_RESULT amvp_set_vendor_info(AMVP_CTX *ctx,
				 const char *vendor_name,
				 const char *vendor_url,
				 const char *contact_name,
				 const char *contact_email)
{
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (ctx->vendor_name) free (ctx->vendor_name);
    if (ctx->vendor_url) free (ctx->vendor_url);
    if (ctx->contact_name) free (ctx->contact_name);
    if (ctx->contact_email) free (ctx->contact_email);

    ctx->vendor_name = strdup(vendor_name);
    ctx->vendor_url = strdup(vendor_url);
    ctx->contact_name = strdup(contact_name);
    ctx->contact_email = strdup(contact_email);

    return AMVP_SUCCESS;
}

/*
 * Allows application to specify the crypto module attributes for
 * the test session.
 */
AMVP_RESULT amvp_set_module_info(AMVP_CTX *ctx,
				 const char *module_name,
				 const char *module_type,
				 const char *module_version,
				 const char *module_description)
{
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (ctx->module_name) free (ctx->module_name);
    if (ctx->module_type) free (ctx->module_type);
    if (ctx->module_version) free (ctx->module_version);
    if (ctx->module_desc) free (ctx->module_desc);

    ctx->module_name = strdup(module_name);
    ctx->module_type = strdup(module_type);
    ctx->module_version = strdup(module_version);
    ctx->module_desc = strdup(module_description);

    return AMVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * AMVP server address and TCP port#.
 */
AMVP_RESULT amvp_set_server(AMVP_CTX *ctx, char *server_name, int port)
{
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (ctx->server_name) free (ctx->server_name);
    ctx->server_name = strdup(server_name);
    ctx->server_port = port;

    return AMVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * AMVP server URI path segment prefix.
 */
AMVP_RESULT amvp_set_path_segment(AMVP_CTX *ctx, char *path_segment)
{
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!path_segment) {
        return AMVP_INVALID_ARG;
    }
    if (ctx->path_segment) free (ctx->path_segment);
    ctx->path_segment = strdup(path_segment);

    return AMVP_SUCCESS;
}

/*
 * This function allows the client to specify the location of the
 * PEM encoded CA certificates that will be used by Curl to verify
 * the AMVP server during the TLS handshake.  If this function is
 * not called by the application, then peer verification is not
 * enabled, which is not recommended (but provided as an operational
 * mode for testing).
 */
AMVP_RESULT amvp_set_cacerts(AMVP_CTX *ctx, char *ca_file)
{
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (ctx->cacerts_file) free (ctx->cacerts_file);
    ctx->cacerts_file = strdup(ca_file);

    /*
     * Enable peer verification when CA certs are provided.
     */
    ctx->verify_peer = 1;

    return AMVP_SUCCESS;
}

/*
 * This function is used to set the X509 certificate and private
 * key that will be used by libamvp during the TLS handshake to
 * identify itself to the server.  Some servers require TLS client
 * authentication, others do not.  This function is optional and
 * should only be used when the AMVP server supports TLS client
 * authentication.
 */
AMVP_RESULT amvp_set_certkey(AMVP_CTX *ctx, char *cert_file, char *key_file)
{
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (ctx->tls_cert) free (ctx->tls_cert);
    ctx->tls_cert = strdup(cert_file);
    if (ctx->tls_key) free (ctx->tls_key);
    ctx->tls_key = strdup(key_file);

    return AMVP_SUCCESS;
}


static AMVP_RESULT amvp_build_hash_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry)
{
    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));
    json_object_set_string(cap_obj, "inBit", cap_entry->cap.hash_cap->in_bit ? "yes" : "no" );
    json_object_set_string(cap_obj, "inEmpty", cap_entry->cap.hash_cap->in_empty ? "yes" : "no" );

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_sym_cipher_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry)
{
    JSON_Array *mode_arr = NULL;
    JSON_Array *opts_arr = NULL;
    AMVP_SL_LIST *sl_list;

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

    /*
     * Set the direction capability
     */
    json_object_set_value(cap_obj, "direction", json_value_init_array());
    mode_arr = json_object_get_array(cap_obj, "direction");
    if (cap_entry->cap.sym_cap->direction == AMVP_DIR_ENCRYPT ||
        cap_entry->cap.sym_cap->direction == AMVP_DIR_BOTH) {
	json_array_append_string(mode_arr, "encrypt");
    }
    if (cap_entry->cap.sym_cap->direction == AMVP_DIR_DECRYPT ||
        cap_entry->cap.sym_cap->direction == AMVP_DIR_BOTH) {
	json_array_append_string(mode_arr, "decrypt");
    }

    /*
     * Set the IV generation source if applicable
     */
    switch(cap_entry->cap.sym_cap->ivgen_source) {
    case AMVP_IVGEN_SRC_INT:
	json_object_set_string(cap_obj, "ivGen", "internal");
	break;
    case AMVP_IVGEN_SRC_EXT:
	json_object_set_string(cap_obj, "ivGen", "external");
	break;
    default:
	/* do nothing, this is an optional capability */
	break;
    }

    /*
     * Set the IV generation mode if applicable
     */
    switch(cap_entry->cap.sym_cap->ivgen_mode) {
    case AMVP_IVGEN_MODE_821:
	json_object_set_string(cap_obj, "ivGenMode", "8.2.1");
	break;
    case AMVP_IVGEN_MODE_822:
	json_object_set_string(cap_obj, "ivGenMode", "8.2.2");
	break;
    default:
	/* do nothing, this is an optional capability */
	break;
    }

    /*
     * Set the TDES keyingOptions  if applicable 
     */
    if (cap_entry->cap.sym_cap->keying_option != AMVP_KO_NA) {
        json_object_set_value(cap_obj, "keyingOption", json_value_init_array());
    	opts_arr = json_object_get_array(cap_obj, "keyingOption");
        if (cap_entry->cap.sym_cap->keying_option == AMVP_KO_THREE ||
            cap_entry->cap.sym_cap->keying_option == AMVP_KO_BOTH) {
	    json_array_append_number(opts_arr, 1);
        }
    	if (cap_entry->cap.sym_cap->keying_option == AMVP_KO_TWO ||
            cap_entry->cap.sym_cap->keying_option == AMVP_KO_BOTH) {
	    json_array_append_number(opts_arr, 2);
        }
    }
    /*
     * Set the supported key lengths
     */
    json_object_set_value(cap_obj, "keyLen", json_value_init_array());
    opts_arr = json_object_get_array(cap_obj, "keyLen");
    sl_list = cap_entry->cap.sym_cap->keylen;
    while (sl_list) {
	json_array_append_number(opts_arr, sl_list->length);
	sl_list = sl_list->next;
    }

    /*
     * Set the supported tag lengths (for AEAD ciphers)
     */
    json_object_set_value(cap_obj, "tagLen", json_value_init_array());
    opts_arr = json_object_get_array(cap_obj, "tagLen");
    sl_list = cap_entry->cap.sym_cap->taglen;
    while (sl_list) {
	json_array_append_number(opts_arr, sl_list->length);
	sl_list = sl_list->next;
    }


    /*
     * Set the supported IV lengths
     */
    json_object_set_value(cap_obj, "ivLen", json_value_init_array());
    opts_arr = json_object_get_array(cap_obj, "ivLen");
    sl_list = cap_entry->cap.sym_cap->ivlen;
    while (sl_list) {
	json_array_append_number(opts_arr, sl_list->length);
	sl_list = sl_list->next;
    }

    /*
     * Set the supported plaintext lengths
     */
    json_object_set_value(cap_obj, "ptLen", json_value_init_array());
    opts_arr = json_object_get_array(cap_obj, "ptLen");
    sl_list = cap_entry->cap.sym_cap->ptlen;
    while (sl_list) {
	json_array_append_number(opts_arr, sl_list->length);
	sl_list = sl_list->next;
    }

    /*
     * Set the supported AAD lengths (for AEAD ciphers)
     */
    json_object_set_value(cap_obj, "aadLen", json_value_init_array());
    opts_arr = json_object_get_array(cap_obj, "aadLen");
    sl_list = cap_entry->cap.sym_cap->aadlen;
    while (sl_list) {
	json_array_append_number(opts_arr, sl_list->length);
	sl_list = sl_list->next;
    }

    return AMVP_SUCCESS;
}

/*
 * This function builds the JSON register message that
 * will be sent to the AMVP server to advertised the crypto
 * capabilities of the module under test.
 */
static AMVP_RESULT amvp_build_register(AMVP_CTX *ctx, char **reg)
{
    AMVP_CAPS_LIST *cap_entry;

    JSON_Value *reg_arry_val  = NULL;
    //JSON_Object *reg_obj = NULL;
    JSON_Value *ver_val  = NULL;
    JSON_Object *ver_obj = NULL;

    JSON_Array *reg_arry = NULL;

    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    JSON_Value *oe_val = NULL;
    JSON_Object *oe_obj = NULL;
    JSON_Value *oee_val = NULL;
    JSON_Object *oee_obj = NULL;
    JSON_Array *caps_arr = NULL;
    JSON_Value *caps_val = NULL;
    JSON_Object *caps_obj = NULL;
    JSON_Value *cap_val = NULL;
    JSON_Object *cap_obj = NULL;
    JSON_Value *vendor_val = NULL;
    JSON_Object *vendor_obj = NULL;
    JSON_Array *con_array_val  = NULL;
    JSON_Array *dep_array_val  = NULL;
    JSON_Value *mod_val  = NULL;
    JSON_Object *mod_obj = NULL;
    JSON_Value *dep_val  = NULL;
    JSON_Object *dep_obj = NULL;
    JSON_Value *con_val  = NULL;
    JSON_Object *con_obj = NULL;

    /*
     * Start the registration array
     */
    reg_arry_val = json_value_init_array();
    //reg_obj = json_value_get_object(reg_arry_val);
    reg_arry = json_array  ((const JSON_Value *)reg_arry_val);

    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, "acvVersion", AMVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    val = json_value_init_object();
    obj = json_value_get_object(val);

    /* TODO: Type of request are under construction, hardcoded for now
     * will need a function amvp_set_request_info() to init
     */
    json_object_set_string(obj, "operation", "register");
    json_object_set_string(obj, "certificateRequest", "yes");
    json_object_set_string(obj, "debugRequest", "no");
    json_object_set_string(obj, "production", "no");
    json_object_set_string(obj, "encryptAtRest", "yes");

    oe_val = json_value_init_object();
    oe_obj = json_value_get_object(oe_val);

    vendor_val = json_value_init_object();
    vendor_obj = json_value_get_object(vendor_val);

    json_object_set_string(vendor_obj, "name", ctx->vendor_name);
    json_object_set_string(vendor_obj, "website", ctx->vendor_url);


    json_object_set_value(vendor_obj, "contact", json_value_init_array());
    con_array_val = json_object_get_array(vendor_obj, "contact");

    con_val = json_value_init_object();
    con_obj = json_value_get_object(con_val);

    json_object_set_string(con_obj, "name", ctx->contact_name);
    json_object_set_string(con_obj, "email", ctx->contact_email);
    json_array_append_value(con_array_val, con_val);

    json_object_set_value(oe_obj, "vendor", vendor_val);

    mod_val = json_value_init_object();
    mod_obj = json_value_get_object(mod_val);

    json_object_set_string(mod_obj, "name", ctx->module_name);
    json_object_set_string(mod_obj, "version", ctx->module_version);
    json_object_set_string(mod_obj, "type", ctx->module_type);
    json_object_set_value(oe_obj, "module", mod_val);

    oee_val = json_value_init_object();
    oee_obj = json_value_get_object(oee_val);

    /* TODO: dependencies are under construction, hardcoded for now
     * will need a function amvp_set_depedency_info() to init
     */
    json_object_set_value(oee_obj, "dependencies", json_value_init_array());
    dep_array_val = json_object_get_array(oee_obj, "dependencies");

    dep_val = json_value_init_object();
    dep_obj = json_value_get_object(dep_val);


    json_object_set_string(dep_obj, "type", "software");
    json_object_set_string(dep_obj, "name", "Linux 3.1");
    json_object_set_string(dep_obj, "cpe", "cpe-2.3:o:ubuntu:linux:3.1");
    json_array_append_value(dep_array_val, dep_val);

    dep_val = json_value_init_object();
    dep_obj = json_value_get_object(dep_val);
    json_object_set_string(dep_obj, "type", "processor");
    json_object_set_string(dep_obj, "manufacturer", "Intel");
    json_object_set_string(dep_obj, "family", "ARK");
    json_object_set_string(dep_obj, "name", "Xeon");
    json_object_set_string(dep_obj, "series", "5100");
    json_array_append_value(dep_array_val, dep_val);

    dep_val = json_value_init_object();
    dep_obj = json_value_get_object(dep_val);

    json_object_set_value(oe_obj, "operationalEnvironment", oee_val);

    json_object_set_string(oe_obj, "implementationDescription", ctx->module_desc);
    json_object_set_value(obj, "oeInformation", oe_val);

    /*
     * Start the capabilities advertisement
     */
    caps_val = json_value_init_object();
    caps_obj = json_value_get_object(caps_val);
    json_object_set_value(caps_obj, "algorithms", json_value_init_array());
    caps_arr = json_object_get_array(caps_obj, "algorithms");

    /*
     * Iterate through all the capabilities the user has enabled
     * TODO: This logic is written for the symmetric cipher sub-spec.
     *       This will need rework when implementing the other
     *       sub-specifications.
     */
    if (ctx->caps_list) {
        cap_entry = ctx->caps_list;
        while (cap_entry) {
            /*
             * Create a new capability to be advertised in the JSON
             * registration message
             */
	    cap_val = json_value_init_object();
	    cap_obj = json_value_get_object(cap_val);

            /*
             * Build up the capability JSON based on the cipher type
             */
            switch(cap_entry->cipher) {
            case AMVP_AES_GCM:
            case AMVP_AES_CCM:
            case AMVP_AES_ECB:
            case AMVP_AES_CFB1:
            case AMVP_AES_CFB8:
            case AMVP_AES_CFB128:
            case AMVP_AES_OFB:
            case AMVP_AES_CBC:
            case AMVP_AES_KW:
            case AMVP_AES_CTR:
            case AMVP_TDES_ECB:
            case AMVP_TDES_CBC:
            case AMVP_TDES_OFB:
            case AMVP_TDES_CFB64:
            case AMVP_TDES_CFB8:
            case AMVP_TDES_CFB1:
		        amvp_build_sym_cipher_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_SHA1:
            case AMVP_SHA224:
            case AMVP_SHA256:
            case AMVP_SHA384:
            case AMVP_SHA512:
		        amvp_build_hash_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_HASHDRBG:
            case AMVP_HMACDRBG:
            case AMVP_CTRDRBG:
                amvp_build_drbg_register_cap(cap_obj, cap_entry);
                break;
            default:
	            amvp_log_msg(ctx, "Cap entry not found, %d.", cap_entry->cipher);
                return AMVP_NO_CAP;
            }

            /*
             * Now that we've built up the JSON for this capability,
             * add it to the array of capabilities on the register message.
             */
	    json_array_append_value(caps_arr, cap_val);

	    /* Advance to next cap entry */
            cap_entry = cap_entry->next;
        }
    }

    /*
     * Add the entire caps exchange section to the top object
     */
    json_object_set_value(obj, "capabilityExchange", caps_val);

    json_array_append_value(reg_arry, val);
    //*reg = json_serialize_to_string(val);
    *reg = json_serialize_to_string_pretty(reg_arry_val);
    json_value_free(reg_arry_val);

    return AMVP_SUCCESS;
}

/*
 * This function is used to regitser the DUT with the server.
 * Registration allows the DUT to advertise it's capabilities to
 * the server.  The server will respond with a set of vector set
 * identifiers that the client will need to process.
 */
AMVP_RESULT amvp_register(AMVP_CTX *ctx)
{
    AMVP_RESULT rv;
    char *reg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Construct the registration message based on the capabilities
     * the user has enabled.
     */
    rv = amvp_build_register(ctx, &reg);
    if (rv != AMVP_SUCCESS) {
        amvp_log_msg(ctx, "Unable to build register message");
        return rv;
    }

    //FIXME
    printf("%s\n", reg);

    /*
     * Send the capabilities to the AMVP server and get the response,
     * which should be a list of VS identifiers that will need
     * to be downloaded and processed.
     */
    rv = amvp_send_register(ctx, reg);
    if (rv == AMVP_SUCCESS) {
        printf("\n%s\n", ctx->reg_buf);
        rv = amvp_parse_register(ctx);
    }

    json_free_serialized_string(reg);

    return (rv);
}

/*
 * Append a VS identifier to the list of VS identifiers
 * that will need to be downloaded and processed later.
 */
static AMVP_RESULT amvp_append_vs_entry(AMVP_CTX *ctx, int vs_id)
{
    AMVP_VS_LIST *vs_entry, *vs_e2;

    vs_entry = calloc(1, sizeof(AMVP_VS_LIST));
    if (!vs_entry) {
        return AMVP_MALLOC_FAIL;
    }
    vs_entry->vs_id = vs_id;

    if (!ctx->vs_list) {
        ctx->vs_list = vs_entry;
    } else {
        vs_e2 = ctx->vs_list;
        while (vs_e2->next) {
            vs_e2 = vs_e2->next;
        }
        vs_e2->next = vs_entry;
    }
    return (AMVP_SUCCESS);
}

/*
 * get version from response
 */
static char* amvp_get_version_from_rsp(JSON_Value *arry_val)
{
    char *version = NULL;
    JSON_Object *ver_obj = NULL;

    JSON_Array  *reg_array;

    reg_array = json_value_get_array(arry_val);
    ver_obj = json_array_get_object(reg_array, 0);
    version = (char *)json_object_get_string(ver_obj, "acvVersion");
    if (version == NULL) {
        return NULL;
    }

    return(version);
}

/*
 * get JASON Object from response
 */
static JSON_Object* amvp_get_obj_from_rsp(JSON_Value *arry_val)
{
    JSON_Object *obj = NULL;
    JSON_Array  *reg_array;
    char        *ver = NULL;

    reg_array = json_value_get_array(arry_val);
    ver = amvp_get_version_from_rsp(arry_val);
    if (ver == NULL) {
        return NULL;
    }

    obj = json_array_get_object(reg_array, 1);
    return(obj);
}

/*
 * This routine performs the JSON parsing of the registration response
 * from the AMVP server.  The response should contain a list of vector
 * set (VS) identifiers that will need to be downloaded and processed
 * by the DUT.
 */
static AMVP_RESULT amvp_parse_register(AMVP_CTX *ctx)
{
    JSON_Value *val;
    JSON_Object *obj = NULL;
    JSON_Object *cap_obj = NULL;
    AMVP_RESULT rv;
    char *json_buf = ctx->reg_buf;
    JSON_Array *vect_sets;
    JSON_Value *vs_val;
    JSON_Object *vs_obj;
    int i, vs_cnt;
    int vs_id;
    const char *jwt;

    /*
     * Parse the JSON
     */
    val = json_parse_string_with_comments(json_buf);
    if (!val) {
        amvp_log_msg(ctx, "JSON parse error");
        return AMVP_JSON_ERR;
    }

    obj = amvp_get_obj_from_rsp(val);

    /*
     * Get the JWT assigned to this session by the server.  This will need
     * to be included when sending the vector responses back to the server
     * later.
     */
    jwt = json_object_get_string(obj, "accessToken");
    if (!jwt) {
        json_value_free(val);
        amvp_log_msg(ctx, "No access_token provided in registration response");
        return AMVP_NO_TOKEN;
    } else {
        i = strnlen(jwt, AMVP_JWT_TOKEN_MAX+1);
        if (i > AMVP_JWT_TOKEN_MAX) {
            json_value_free(val);
            amvp_log_msg(ctx, "access_token too large");
            return AMVP_NO_TOKEN;
        }
        ctx->jwt_token = calloc(1, i+1);
        strncpy(ctx->jwt_token, jwt, i);
        ctx->jwt_token[i] = 0;
        amvp_log_msg(ctx, "JWT: %s", ctx->jwt_token);
    }

    /*
     * Identify the VS identifiers provided by the server, save them for
     * processing later.
     */
    cap_obj = json_object_get_object(obj, "capabilityResponse");
    //const char *op = json_object_get_string(obj, "operation");
    vect_sets = json_object_get_array(cap_obj, "vectorSets");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        vs_val = json_array_get_value(vect_sets, i);
        vs_obj = json_value_get_object(vs_val);
        vs_id = json_object_get_number(vs_obj, "vsId");

        rv = amvp_append_vs_entry(ctx, vs_id);
        if (rv != AMVP_SUCCESS) {
            json_value_free(val);
            return rv;
        }
        amvp_log_msg(ctx, "Received vs_id=%d", vs_id);
    }

    json_value_free(val);

    amvp_log_msg(ctx, "Successfully processed registration response from server");

    return AMVP_SUCCESS;

}

/*
 * This function is used by the application after registration
 * to commence the testing.  All the testing will be handled
 * by libamvp.  This function will block the caller.  Therefore,
 * it should be run on a separate thread if needed.
 */
AMVP_RESULT amvp_process_tests(AMVP_CTX *ctx)
{
    AMVP_RESULT rv;
    AMVP_VS_LIST *vs_entry;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Iterate through the VS identifiers the server sent to us
     * in the regisration response.  Process each vector set and
     * return the results to the server.
     */
    vs_entry = ctx->vs_list;
    while (vs_entry) {
        rv = amvp_process_vsid(ctx, vs_entry->vs_id);
        vs_entry = vs_entry->next;
    }

    return (rv);
}

/*
 * This is a minimal retry handler, which pauses for a specific time.
 * This allows the server time to generate the vectors on behalf of
 * the client.
 */
AMVP_RESULT amvp_retry_handler(AMVP_CTX *ctx, unsigned int retry_period)
{
    amvp_log_msg(ctx, "KAT values not ready, server requests we wait and try again...");
    if (retry_period <= 0 || retry_period > AMVP_RETRY_TIME_MAX) {
        retry_period = AMVP_RETRY_TIME_MAX;
        amvp_log_msg(ctx, "Warning: retry_period not found, using max retry period!");
    }
    sleep(retry_period);

    return AMVP_KAT_DOWNLOAD_RETRY;
}


/*
 * This routine will iterate through all the vector sets, requesting
 * the test result from the server for each set.
 */
AMVP_RESULT amvp_check_test_results(AMVP_CTX *ctx)
{
    AMVP_RESULT rv;
    AMVP_VS_LIST *vs_entry;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Iterate through the VS identifiers the server sent to us
     * in the regisration response.  Attempt to download the result
     * for each vector set.
     */
    vs_entry = ctx->vs_list;
    while (vs_entry) {
        rv = amvp_get_result_vsid(ctx, vs_entry->vs_id);
        vs_entry = vs_entry->next;
    }

    return (rv);
}



/***************************************************************************************************************
* Begin vector processing logic.  This code should probably go into another module.
***************************************************************************************************************/


/*
 * This function will process a single KAT vector set.  Each KAT
 * vector set has an identifier associated with it, called
 * the vs_id.  During registration, libamvp will receive the
 * list of vs_id's that need to be processed during the test
 * session.  This routine will execute the test flow for a single
 * vs_id.  The flow is:
 *	a) Download the KAT vector set from the server using the vs_id
 *	b) Parse the KAT vectors
 *	c) Process each test case in the KAT vector set
 *	d) Generate the response data
 *	e) Send the response data back to the AMVP server
 */
static AMVP_RESULT amvp_process_vsid(AMVP_CTX *ctx, int vs_id)
{
    AMVP_RESULT rv;
    JSON_Value *val;
    JSON_Object *obj = NULL;
    char *json_buf;
    int retry = 1;

    //TODO: do we want to limit the number of retries?
    while (retry) {
        /*
         * Get the KAT vector set
         */
        rv = amvp_retrieve_vector_set(ctx, vs_id);
        if (rv != AMVP_SUCCESS) {
            return (rv);
        }
        json_buf = ctx->kat_buf;
        printf("\n%s\n", ctx->kat_buf);
        val = json_parse_string_with_comments(json_buf);
        if (!val) {
            amvp_log_msg(ctx, "JSON parse error");
            return AMVP_JSON_ERR;
        }
        obj = amvp_get_obj_from_rsp(val);
        ctx->vs_id = vs_id;

        /*
         * Check if we received a retry response
         */
        unsigned int retry_period = json_object_get_number(obj, "retry");
        if (retry_period) {
            rv = amvp_retry_handler(ctx, retry_period);
        } else {
            /*
             * Process the KAT vectors
             */
            rv = amvp_process_vector_set(ctx, obj);
        }
        json_value_free(val);

        /*
         * Check if we need to retry the download because
         * the KAT values were not ready
         */
        if (AMVP_KAT_DOWNLOAD_RETRY == rv) {
            retry = 1;
        } else if (rv != AMVP_SUCCESS) {
            return (rv);
        } else {
            retry = 0;
        }
    }

    /*
     * Send the responses to the AMVP server
     */
    rv = amvp_submit_vector_responses(ctx);
    if (rv != AMVP_SUCCESS) {
        return (rv);
    }

    return AMVP_SUCCESS;
}


/*
 * This function is used to invoke the appropriate handler function
 * for a given ACV operation.  The operation is specified in the
 * KAT vector set that was previously downloaded.  The handler function
 * is looked up in the alg_tbl[] and invoked here.
 */
static AMVP_RESULT amvp_dispatch_vector_set(AMVP_CTX *ctx, JSON_Object *obj)
{
    int i;
    const char *alg = json_object_get_string(obj, "algorithm");
    const char *dir = json_object_get_string(obj, "direction");
    int vs_id = json_object_get_number(obj, "vsId");
    AMVP_RESULT rv;

    if (!alg) {
        amvp_log_msg(ctx, "JSON parse error: ACV algorithm not found");
        return AMVP_JSON_ERR;
    }

    amvp_log_msg(ctx, "vsId: %d", vs_id);
    amvp_log_msg(ctx, "ACV Operation: %s", alg);
    amvp_log_msg(ctx, "ACV Direction: %s", dir);
    amvp_log_msg(ctx, "ACV version: %s", json_object_get_string(obj, "acvVersion"));

    for (i = 0; i < AMVP_ALG_MAX; i++) {
        if (!strncmp(alg, alg_tbl[i].name, strlen(alg_tbl[i].name))) {
            rv = (alg_tbl[i].handler)(ctx, obj);
            return rv;
        }
    }
    return AMVP_UNSUPPORTED_OP;
}

/*
 * This function is used to process the test cases for
 * a given KAT vector set.  This is invoked after the
 * KAT vector set has been downloaded from the server.  The
 * vectors are stored on the AMVP_CTX in one of the
 * transitory fields.  Therefore, the vs_id isn't needed
 * here to know which vectors need to be processed.
 *
 * The processing logic is:
 *	a) JSON parse the data
 *	b) Identify the AMVP operation to be performed (e.g. AES encrypt)
 *	c) Dispatch the vectors to the handler for the
 *	   specified AMVP operation.
 */
static AMVP_RESULT amvp_process_vector_set(AMVP_CTX *ctx, JSON_Object *obj)
{
    AMVP_RESULT rv;

    rv = amvp_dispatch_vector_set(ctx, obj);
    if (rv != AMVP_SUCCESS) {
        return rv;
    }

    amvp_log_msg(ctx, "Successfully processed KAT vector set");

    return AMVP_SUCCESS;

}


/*
 * This function will get the test results for a single KAT vector set.
 */
static AMVP_RESULT amvp_get_result_vsid(AMVP_CTX *ctx, int vs_id)
{
    AMVP_RESULT rv;
    JSON_Value *val;
    JSON_Object *obj = NULL;
    char *json_buf;
    int retry = 1;

    //TODO: do we want to limit the number of retries?
    while (retry) {
        /*
         * Get the KAT vector set
         */
        rv = amvp_retrieve_vector_set_result(ctx, vs_id);
        if (rv != AMVP_SUCCESS) {
            return (rv);
        }
        json_buf = ctx->kat_buf;
        printf("\n%s\n", ctx->kat_buf);
        val = json_parse_string_with_comments(json_buf);
        if (!val) {
            amvp_log_msg(ctx, "JSON parse error");
            return AMVP_JSON_ERR;
        }
        obj = amvp_get_obj_from_rsp(val);
        ctx->vs_id = vs_id;

        /*
         * Check if we received a retry response
         */
        unsigned int retry_period = json_object_get_number(obj, "retry");
        if (retry_period) {
            rv = amvp_retry_handler(ctx, retry_period);
        } else {
	    /*
	     * Parse the JSON response from the server, if the vector set failed,
	     * then pull out the reason code and log it.
	     */
	    //TODO
        }
        json_value_free(val);

        /*
         * Check if we need to retry the download because
         * the KAT values were not ready
         */
        if (AMVP_KAT_DOWNLOAD_RETRY == rv) {
            retry = 1;
        } else if (rv != AMVP_SUCCESS) {
            return (rv);
        } else {
            retry = 0;
        }
    }

    return AMVP_SUCCESS;
}
