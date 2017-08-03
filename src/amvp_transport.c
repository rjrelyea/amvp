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
#ifdef USE_MURL
# include <murl/murl.h>
#else
# include <curl/curl.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "amvp.h"
#include "amvp_lcl.h"

#define HTTP_OK    200

#define MAX_TOKEN_LEN 512 
static struct curl_slist* amvp_add_auth_hdr (AMVP_CTX *ctx, struct curl_slist *slist)
{
    int bearer_size;
    char *bearer;

    /*
     * Create the Authorzation header if needed
     */
    if (ctx->jwt_token) {
    	bearer_size = strnlen(ctx->jwt_token, MAX_TOKEN_LEN) + 23;
    	bearer = calloc(1, bearer_size);
	if (!bearer) {
	    amvp_log_msg(ctx, "ERROR: unable to allocate memory.");
	    return slist;
	}
        snprintf(bearer, bearer_size + 1, "Authorization: Bearer %s", ctx->jwt_token);
        slist = curl_slist_append(slist, bearer);
        free(bearer);
    }
    return slist;
}


/*
 * This routine will log the TLS peer certificate chain, which
 * allows auditing the peer identity by inspecting the logs.
 */
static void amvp_curl_log_peer_cert (AMVP_CTX *ctx, CURL *hnd) 
{
    int rv; 
    union {
        struct curl_slist    *to_info;
        struct curl_certinfo *to_certinfo;
    } ptr;
    int i;
    struct curl_slist *slist;
 
    ptr.to_info = NULL;
 
    rv = curl_easy_getinfo(hnd, CURLINFO_CERTINFO, &ptr.to_info);
 
    if(!rv && ptr.to_info) {
	amvp_log_msg(ctx, "TLS peer presented the following %d certificates...", ptr.to_certinfo->num_of_certs);
        for(i = 0; i < ptr.to_certinfo->num_of_certs; i++) {
            for(slist = ptr.to_certinfo->certinfo[i]; slist; slist = slist->next) {
		amvp_log_msg(ctx, "%s", slist->data);
	    }
        }
    }
}

/*
 * This function uses libcurl to send a simple HTTP GET
 * request with no Content-Type header.
 * TLS peer verification is enabled, but not HTTP authentication.
 * The parameters are:
 *
 * ctx: Ptr to AMVP_CTX, which contains the server name
 * url: URL to use for the GET request
 * writefunc: Function pointer to handle writing the data
 *            from the HTTP body received from the server.
 *
 * Return value is the HTTP status value from the server
 *	    (e.g. 200 for HTTP OK)
 */
static long amvp_curl_http_get (AMVP_CTX *ctx, char *url, void *writefunc)
{
    long http_code = 0;
    CURL *hnd;
    struct curl_slist *slist;
printf("amvp_get: url=%s\n", url);

    slist = NULL;
    /*
     * Create the Authorzation header if needed
     */
    slist = amvp_add_auth_hdr(ctx, slist);

    ctx->read_ctr = 0;

    /*
     * Setup Curl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, url);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.27.0");
    if (slist) {
        curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
    }
    if (ctx->verify_peer && ctx->cacerts_file) {
        curl_easy_setopt(hnd, CURLOPT_CAINFO, ctx->cacerts_file);
        curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(hnd, CURLOPT_CERTINFO, 1L);
    } else {
        curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
        amvp_log_msg(ctx, "WARNING: TLS peer verification has not been enabled.");
    }
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    if (ctx->tls_cert && ctx->tls_key) {
        curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(hnd, CURLOPT_SSLCERT, ctx->tls_cert);
        curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
        curl_easy_setopt(hnd, CURLOPT_SSLKEY, ctx->tls_key);
    }
    /*
     * If the caller wants the HTTP data from the server
     * set the callback function
     */
    if (writefunc) {
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, ctx);
        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writefunc);
    }

    /*
     * Send the HTTP GET request
     */
    curl_easy_perform(hnd);

    /*
     * Get the cert info from the TLS peer
     */
    if (ctx->verify_peer) {
	amvp_curl_log_peer_cert(ctx, hnd); 
    }

    /*
     * Get the HTTP reponse status code from the server
     */
    curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != HTTP_OK) {
	amvp_log_msg(ctx, "HTTP response: %d\n", (int)http_code);
    } 

    curl_easy_cleanup(hnd);
    hnd = NULL;
    if (slist) {
        curl_slist_free_all(slist);
        slist = NULL;
    }

    return (http_code);
}

/*
 * This function uses libcurl to send a simple HTTP POST
 * request with no Content-Type header.
 * TLS peer verification is enabled, but not HTTP authentication.
 * The parameters are:
 *
 * ctx: Ptr to AMVP_CTX, which contains the server name
 * url: URL to use for the GET request
 * data: data to POST to the server
 * writefunc: Function pointer to handle writing the data
 *            from the HTTP body received from the server.
 *
 * Return value is the HTTP status value from the server
 *	    (e.g. 200 for HTTP OK)
 */
static long amvp_curl_http_post (AMVP_CTX *ctx, char *url, char *data, void *writefunc)
{
    long http_code = 0;
    CURL *hnd;
    CURLcode crv;
    struct curl_slist *slist;
printf("amvp_post: url=%s\n", url);

    /*
     * Set the Content-Type header in the HTTP request
     */
    slist = NULL;
    slist = curl_slist_append(slist, "Content-Type:application/octet-stream");
    //FIXME: v0.2 spec says to use application/json
    //slist = curl_slist_append(slist, "Content-Type:application/json");
    
    /*
     * Create the Authorzation header if needed
     */
    slist = amvp_add_auth_hdr(ctx, slist);

    ctx->read_ctr = 0;

    /*
     * Setup Curl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, url);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "libamvp");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_POST, 1L);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(data));
    //FIXME: we should always to TLS peer auth
    if (ctx->verify_peer && ctx->cacerts_file) {
        curl_easy_setopt(hnd, CURLOPT_CAINFO, ctx->cacerts_file);
        curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(hnd, CURLOPT_CERTINFO, 1L);
    } else {
        curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
        amvp_log_msg(ctx, "WARNING: TLS peer verification has not been enabled.");
    }
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    if (ctx->tls_cert && ctx->tls_key) {
        curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(hnd, CURLOPT_SSLCERT, ctx->tls_cert);
        curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
        curl_easy_setopt(hnd, CURLOPT_SSLKEY, ctx->tls_key);
    }

    /*
     * If the caller wants the HTTP data from the server
     * set the callback function
     */
    if (writefunc) {
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, ctx);
        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writefunc);
    }

    /*
     * Send the HTTP POST request
     */
    crv = curl_easy_perform(hnd);
    if (crv != CURLE_OK) {
        amvp_log_msg(ctx, "Curl failed with code %d (%s)\n", crv, curl_easy_strerror(crv));
    }

    /*
     * Get the cert info from the TLS peer
     */
    if (ctx->verify_peer) {
	amvp_curl_log_peer_cert(ctx, hnd); 
    }

    /*
     * Get the HTTP reponse status code from the server
     */
    curl_easy_getinfo (hnd, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != HTTP_OK) {
	amvp_log_msg(ctx, "HTTP response: %d\n", (int)http_code);
    }

    curl_easy_cleanup(hnd);
    hnd = NULL;
    curl_slist_free_all(slist);
    slist = NULL;

    return (http_code);
}

#define AMVP_BUF_MAX 4096

/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * on the AMVP_CTX in one of the transitory fields.
 */
static size_t amvp_curl_write_upld_func(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    AMVP_CTX *ctx = (AMVP_CTX*)userdata;
    char *http_buf;

    if (size != 1) {
        fprintf(stderr, "\ncurl size not 1\n");
        return 0;
    }

    if (!ctx->upld_buf) {
        ctx->upld_buf = calloc(1, AMVP_BUF_MAX);
        if (!ctx->upld_buf) {
            fprintf(stderr, "\nmalloc failed in curl write upld func\n");
            return 0;
        }
    }
    http_buf = ctx->upld_buf;

    if ((ctx->read_ctr + nmemb) > AMVP_BUF_MAX) {
        fprintf(stderr, "\nKAT is too large\n");
        return 0;
    }

    memcpy(&http_buf[ctx->read_ctr], ptr, nmemb);
    http_buf[ctx->read_ctr+nmemb] = 0;
    ctx->read_ctr += nmemb;

    return nmemb;
}


#ifdef notdef
/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * on the AMVP_CTX in one of the transitory fields.
 */
static size_t amvp_curl_write_kat_func(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    AMVP_CTX *ctx = (AMVP_CTX*)userdata;
    char *json_buf;

    if (size != 1) {
        fprintf(stderr, "\ncurl size not 1\n");
        return 0;
    }

    if (!ctx->kat_buf) {
        ctx->kat_buf = calloc(1, AMVP_KAT_BUF_MAX);
        if (!ctx->kat_buf) {
            fprintf(stderr, "\nmalloc failed in curl write kat func\n");
            return 0;
        }
    }
    json_buf = ctx->kat_buf;

    if ((ctx->read_ctr + nmemb) > AMVP_KAT_BUF_MAX) {
        fprintf(stderr, "\nKAT is too large\n");
        return 0;
    }

    memcpy(&json_buf[ctx->read_ctr], ptr, nmemb);
    json_buf[ctx->read_ctr+nmemb] = 0;
    ctx->read_ctr += nmemb;

    return nmemb;
}
#endif

/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * on the AMVP_CTX in one of the transitory fields.
 */
static size_t amvp_curl_write_register_func(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    AMVP_CTX *ctx = (AMVP_CTX*)userdata;
    char *json_buf;

    if (size != 1) {
        fprintf(stderr, "\ncurl size not 1\n");
        return 0;
    }

    if (!ctx->reg_buf) {
        ctx->reg_buf = calloc(1, AMVP_REG_BUF_MAX);
        if (!ctx->reg_buf) {
            fprintf(stderr, "\nmalloc failed in curl write reg func\n");
            return 0;
        }
    }
    json_buf = ctx->reg_buf;

    if ((ctx->read_ctr + nmemb) > AMVP_REG_BUF_MAX) {
        fprintf(stderr, "\nRegister response is too large\n");
        return 0;
    }

    memcpy(&json_buf[ctx->read_ctr], ptr, nmemb);
    json_buf[ctx->read_ctr+nmemb] = 0;
    ctx->read_ctr += nmemb;

    return nmemb;
}


/*
 * This is the transport function used within libamvp to register
 * the DUT with the AMVP server.
 *
 * The reg parameter is the JSON encoded registration message that
 * will be sent to the server.
 */
AMVP_RESULT amvp_send_register(AMVP_CTX *ctx, char *reg)
{
    int rv;
    char url[512]; //TODO: 512 is an arbitrary limit

    memset(url, 0x0, 512);
    snprintf(url, 511, "https://%s:%d/%svalidation/amvp/register", ctx->server_name, ctx->server_port, ctx->path_segment);

    rv = amvp_curl_http_post(ctx, url, reg, &amvp_curl_write_register_func);
    if (rv != HTTP_OK) {
        amvp_log_msg(ctx, "Unable to register with AMVP server. curl rv=%d\n", rv);
	amvp_log_msg(ctx, "%s\n", ctx->reg_buf);
        return AMVP_TRANSPORT_FAIL;
    }

    /*
     * Update user with status
     */
    amvp_log_msg(ctx,"Successfully received registration response from AMVP server");

    return AMVP_SUCCESS;
}




