/** @file
 *  This is the public header file to be included by applications
 *  using libamvp.
 */
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
#ifndef amvp_h
#define amvp_h

#ifdef __cplusplus
extern "C"
{
#endif

/*! @struct AMVP_CTX
 *  @brief This opaque structure is used to maintain the state of a test session
 *         with an AMVP server.  A single instance of this context
 *         represents a test session with the AMVP server.  This context
 *         is used by the application layer to perform the steps to
 *         conduct a test.  These steps are:
 *
 *         1. Create the context
 *         2. Specify the server hostname
 *         3. Specify the crypto algorithms to test
 *         4. Register with the AMVP server
 *         5. Commence the test with the server
 *         6. Check the test results
 *         7. Free the context
 */
typedef struct amvp_ctx_t AMVP_CTX;

/*! @struct AMVP_RESULT
 *  @brief This enum is used to indicate error conditions to the appplication
 *     layer. Most libamvp function will return a value from this enum.
 *
 *     TODO: document all the error codes
 */
typedef enum amvp_result AMVP_RESULT;

/*
 * These are the available symmetric algorithms that libamvp supports.  The application
 * layer will need to register one or more of these based on the capabilities
 * of the crypto module being validated.
 *
 * **************** ALERT *****************
 * This enum must stay aligned with test_tbl[] in amvp.c
 */
typedef enum amvp_test {
    AMVP_TE01_03_02 = 0,
    AMVP_TE01_04_02,
    AMVP_TE02_06_02,
    AMVP_TE02_06_04,
    AMVP_TE02_13_03,
    AMVP_TE02_14_02,
    AMVP_TE03_02_02,
    AMVP_TE03_11_02,
    AMVP_TE03_11_03,
    AMVP_TE03_03_02,
    AMVP_TE03_14_02,
    AMVP_TE03_15_02,
    AMVP_TE03_17_02,
    AMVP_TE03_18_02,
    AMVP_TE03_21_02,
    AMVP_TE03_22_02,
    AMVP_TE03_23_02,
    AMVP_TE03_24_02,
    AMVP_TE04_03_01,
    AMVP_TE04_05_08,
    AMVP_TE07_01_02,
    AMVP_TE07_02_02,
    AMVP_TE07_15_02,
    AMVP_TE07_15_03,
    AMVP_TE07_15_04,
    AMVP_TE07_23_03,
    AMVP_TE07_25_02,
    AMVP_TE07_27_02,
    AMVP_TE07_29_02,
    AMVP_TE07_32_02,
    AMVP_TE07_39_02,
    AMVP_TE07_41_02,
    AMVP_TE09_04_03,
    AMVP_TE09_05_03,
    AMVP_TE09_06_02,
    AMVP_TE09_07_03,
    AMVP_TE09_09_02,
    AMVP_TE09_10_02,
    AMVP_TE09_12_02,
    AMVP_TE09_16_01,
    AMVP_TE09_16_02,
    AMVP_TE09_19_03,
    AMVP_TE09_22_07,
    AMVP_TE09_24_01,
    AMVP_TE09_27_01,
    AMVP_TE09_27_02,
    AMVP_TE09_31_01,
    AMVP_TE09_33_01,
    AMVP_TE09_35_04,
    AMVP_TE09_35_05,
    AMVP_TEST_END
} AMVP_TEST;

typedef enum amvp_test_response {
    AMVP_TEST_PASSED_WITH_LOG = 0,
    AMVP_TEST_FAILED_WITH_LOG,
    AMVP_TEST_FAILED,
    AMVP_TEST_NOT_IMPLEMENTED,
    AMVP_TEST_NOT_RELEVANT
} AMVP_TEST_RESPONSE;

typedef struct amvp_tc_t AMVP_TEST_CASE;
typedef void (*AMVP_CLEANUP_FUNC)(AMVP_TEST_CASE *tc);
typedef AMVP_RESULT (*AMVP_TEST_HANDLER_CALLBACK)(AMVP_CTX *ctx, 
                                                  AMVP_TEST_CASE *test_case);

/*
 * This struct holds data that represents a single test case .
 * This data is passed between libamvp and the crypto module.  libamvp will 
 * parse the test case parameters from the JSON encoded test vector, 
 * fill in this structure, and pass the struct to the crypto module via the
 * handler that was registered with libamvp.  The crypto module will
 * then need to perform the TE test and fill in the log
 * items in the struct for the given test case.  The struct is then
 * passed back to libamvp, where it is then used to build the JSON
 * encoded vector response.
 */
#define AMVP_MAX_LOG_COUNT 3
struct amvp_tc_t {
    AMVP_TEST       test_type;
    const char      *test_name;
    unsigned int    mt_id;    /* Test case id */
    AMVP_TEST_RESPONSE test_response;
    unsigned int    log_count;
    const char      *log[AMVP_MAX_LOG_COUNT];
    const char      *info;
    AMVP_CLEANUP_FUNC cleanup;
};

enum amvp_result {
    AMVP_SUCCESS = 0,
    AMVP_MALLOC_FAIL,
    AMVP_NO_CTX,
    AMVP_TRANSPORT_FAIL,
    AMVP_JSON_ERR,
    AMVP_UNSUPPORTED_TEST,
    AMVP_CLEANUP_FAIL,
    AMVP_KAT_DOWNLOAD_RETRY,
    AMVP_INVALID_ARG,
    AMVP_CRYPTO_MODULE_FAIL,
    AMVP_NO_TOKEN,
    AMVP_NO_CAP,
    AMVP_MALFORMED_JSON,
    AMVP_DATA_TOO_LARGE,
    AMVP_DUP_CIPHER,
    AMVP_RESULT_MAX,
    AMVP_DBG_ERR,
    AMVP_DBG_PARSE_ERR,
    AMVP_DBG_UNKNOWN_BREAKPOINT,
    AMVP_RESOURCE_FAIL
};

/*! @brief amvp_create_test_session() creates a context that can be used to
      commence a test session with an AMVP server.

    This function should be called first to create a context that is used
    to manage all the API calls into libamvp.  The context should be released
    after the test session has completed by invoking amvp_free_test_session().

    When creating a new test session, a function pointer can be provided
    to receive logging messages from libamvp.  The application can then
    forward the log messages to any logging service it desires, such as
    syslog.

    @param ctx Address of pointer to unallocated AMVP_CTX.
    @param progress_cb Address of function to receive log messages from libamvp.

    @return AMVP_RESULT
 */
AMVP_RESULT amvp_create_test_session(AMVP_CTX **ctx, AMVP_RESULT (*progress_cb)(char *msg));

/*! @brief amvp_free_test_session() releases the memory associated with
       an AMVP_CTX.

    This function will free an AMVP_CTX.  Failure to invoke this function
    will result in a memory leak in the application layer.  This function should
    be invoked after a test session has completed and a reference to the context
    is no longer needed.

    @param ctx Pointer to AMVP_CTX that was previously created by
        calling amvp_create_test_session.

    @return AMVP_RESULT
 */
AMVP_RESULT amvp_free_test_session(AMVP_CTX *ctx);

/*! @brief amvp_set_server() specifies the AMVP server and TCP port
       number to use when contacting the server.

    This function is used to specify the hostname or IP address of
    the AMVP server.  The TCP port number can also be specified if the
    server doesn't use port 443.

    @param ctx Pointer to AMVP_CTX that was previously created by
        calling amvp_create_test_session.
    @param server_name Name or IP address of the AMVP server.
    @param port TCP port number the server listens on.

    @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_server(AMVP_CTX *ctx, char *server_name, int port);

/*! @brief amvp_set_path_segment() specifies the URI prefix used by
       the AMVP server.

    Some AMVP servers use a prefix in the URI for the path to the AMVP
    REST interface.  Calling this function allows the path segment
    prefix to be specified.  The value provided to this function is
    prepended to the path segment of the URI used for the AMVP
    REST calls.

    @param ctx Pointer to AMVP_CTX that was previously created by
        calling amvp_create_test_session.
    @param path_segment Value to embed in the URI path after the server name and
       before the AMVP well-known path.

    @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_path_segment(AMVP_CTX *ctx, char *path_segment);

/*! @brief amvp_set_cacerts() specifies PEM encoded certificates to use
       as the root trust anchors for establishing the TLS session with
       the AMVP server.

    AMVP uses TLS as the transport.  In order to verify the identity of
    the AMVP server, the TLS stack requires one or more root certificates
    that can be used to verify the identify of the AMVP TLS certificate
    during the TLS handshake.  These root certificates are set using
    this function.  They must be PEM encoded and all contained in the
    same file.

    @param ctx Pointer to AMVP_CTX that was previously created by
        calling amvp_create_test_session.
    @param ca_file Name of file containing all the PEM encoded X.509 certificates used
       as trust anchors for the TLS session.

    @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_cacerts(AMVP_CTX *ctx, char *ca_file);

/*! @brief amvp_set_certkey() specifies PEM encoded certificate and
       private key to use for establishing the TLS session with the
       AMVP server.

    AMVP uses TLS as the transport.  In order for the AMVP server to
    verify the identity the DUT using libamvp, a certificate needs to
    be presented during the TLS handshake.  The certificate used by libamvp
    needs to be trusted by the AMVP server.  Otherwise the TLS handshake
    will fail.

    @param ctx Pointer to AMVP_CTX that was previously created by
        calling amvp_create_test_session.
    @param cert_file Name of file containing the PEM encoded X.509 certificate to
       use as the client identity.
    @param key_file Name of file containing PEM encoded private key associated with
       the client certificate.

    @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_certkey(AMVP_CTX *ctx, char *cert_file, char *key_file);

/*! @brief amvp_register() registers the DUT with the AMVP server.

    This function is used to regitser the DUT with the server.
    Registration allows the DUT to advertise it's capabilities to
    the server.  The server will respond with a set of vector set
    identifiers that the client will need to process.

    @param ctx Pointer to AMVP_CTX that was previously created by
        calling amvp_create_test_session.

    @return AMVP_RESULT
 */
AMVP_RESULT amvp_register(AMVP_CTX *ctx);

/*! @brief amvp_process_tests() performs the AMVP testing procedures.

    This function will commence the test session after the DUT has
    been registered with the AMVP server.  This function should be
    invoked after amvp_register() finishes.  When invoked, this function
    will download the vector sets from the AMVP server, process the
    vectors, and upload the results to the server.

    @param ctx Pointer to AMVP_CTX that was previously created by
        calling amvp_create_test_session.

    @return AMVP_RESULT
 */
AMVP_RESULT amvp_process_tests(AMVP_CTX *ctx);

/*! @brief amvp_set_vendor_info() specifies the vendor attributes
    for the test session.

    @param ctx Pointer to AMVP_CTX that was previously created by
        calling amvp_create_test_session.
    @param vendor_name Name of the vendor that owns the crypto module.
    @param vendor_url The Vendor's URL.
    @param contact_name Name of contact at Vendor.
    @param contact_email Email of vendor contact.

    @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_vendor_info(AMVP_CTX *ctx,
				 const char *vendor_name,
				 const char *vendor_url,
				 const char *contact_name,
				 const char *contact_email);

/*! @brief amvp_set_module_info() specifies the crypto module attributes
    for the test session.

    @param ctx Pointer to AMVP_CTX that was previously created by
        calling amvp_create_test_session.
    @param module_name Name of the crypto module under test.
    @param module_type The crypto module type: software, hardware, or hybrid.
    @param module_version The version# of the crypto module under test.
    @param module_description A brief description of the crypto module under test.

    @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_module_info(AMVP_CTX *ctx,
				 const char *module_name,
				 const char *module_type,
				 const char *module_version,
				 const char *module_description);

AMVP_RESULT amvp_check_test_results(AMVP_CTX *ctx);
void amvp_cleanup(void);

const char * amvp_lookup_test_name(AMVP_TEST test_type);
AMVP_TEST amvp_lookup_test_type(const char *test_name);


/*
 * This particular test has not been implemented by your module yet
 */
AMVP_RESULT amvp_not_implemented(AMVP_TEST_CASE *tc);

/*
 * This particular test has not apply to your module 
 */
AMVP_RESULT amvp_does_not_apply(AMVP_TEST_CASE *tc, const char *info);

#ifdef __cplusplus
}
#endif

#endif
