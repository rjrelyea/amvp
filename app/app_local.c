/*
 * 
 */
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "amvp.h"
#include "app_lcl.h"

int main(int argc, char **argv)
{
     AMVP_TEST_CASE test_case;
     AMVP_TEST test_type;
     AMVP_RESULT rv;
     int test_count =0;
     int passed_count =0;
     int failed_count =0;
     int sys_failed_count =0;
     int unimplemented_count =0;
     int irrelevant_count =0;
     int bad_rc_count =0;

     for (test_type = 0; test_type < AMVP_TEST_END; test_type ++) {
	test_count++;
	memset (&test_case, 0, sizeof(test_case));
	test_case.test_type = test_type;
	test_case.tc_id = test_type;
	rv = amvp_handle_test(&test_case);
	printf("--------------------------------- TEST %2d ---------------------------------\n", test_case.test_type);
	printf(" return %d\n", rv);
	if (rv != AMVP_SUCCESS) {
	    sys_failed_count++;
	}
	switch (test_case.test_response) {
	case AMVP_TEST_PASSED_WITH_LOG:
	    passed_count++;
	    printf(" result: AMVP_TEST_PASSED_WITH_LOG\n");
	    break;
	case AMVP_TEST_FAILED_WITH_LOG:
	    failed_count++;
	    printf(" result: AMVP_TEST_FAILED_WITH_LOG\n");
	    break;
	case AMVP_TEST_FAILED:
	    failed_count++;
	    printf(" result: AMVP_TEST_FAILED\n");
	    break;
	case AMVP_TEST_NOT_IMPLEMENTED:
	    unimplemented_count++;
	    printf(" result: AMVP_TEST_NOT_IMPLEMENTED\n");
	    break;
	case AMVP_TEST_NOT_RELEVANT:
	    irrelevant_count++;
	    printf(" result: AMVP_TEST_NOT_RELEVANT\n");
	    break;
	default:
	    bad_rc_count++;
	    printf(" result: UNKNOWN response %d\n", test_case.test_response);
	}
	if (test_case.info) {
	    printf("     ---------  info ----------\n");
	    printf("%s\n",test_case.info);
	}
	if (test_case.log_count != 0) {
	    int i;
	    printf("     ---------  logs ----------\n");
	    printf(" log count: %d\n",test_case.log_count);
	    for (i=0; i < test_case.log_count; i++) {
		printf("            ---------  log %d ----------\n",i);
		printf("%s\n",test_case.log[i]);
	    }
	}
	if (test_case.cleanup) {
	    test_case.cleanup(&test_case);
	}
    }
    printf("-----------------------------------------------------------------------------\n");
    printf("Total Tests: %d\n", test_count);
    printf("Passing Tests: %d (%d%%)\n", passed_count, 
					(passed_count*100)/test_count);
    printf("Irrelevant Tests: %d (%d%%)\n", irrelevant_count, 
					(irrelevant_count*100)/test_count);
    printf("Failing Tests: %d (%d%%)\n", failed_count,
					(failed_count*100)/test_count);
    printf("Unimplemented Tests: %d (%d%%)\n", unimplemented_count,
					(unimplemented_count*100)/test_count);
    printf("Bad Response Codes: %d (%d%%)\n", bad_rc_count,
					(bad_rc_count*100)/test_count);
    printf("----------------\n");
    printf("system errors: %d (%d%%)\n",sys_failed_count,
					(sys_failed_count*100)/test_count);
    return 0;
}
	

