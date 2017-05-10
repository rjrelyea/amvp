/*
 * 
 */
AMVP_RESULT does_not_apply(AMVP_TEST_CASE *tc, const char *info)
{
	tc->test_responce = AMVP_TEST_NOT_RELEVANT;
	tc->logcount = 0;
	tc->info = info;
	return AMVP_SUCCESS;
}

AMVP_RESULT not_implemented_yet(AMVP_TEST_CASE *tc)
{
	tc->test_responce = AMVP_TEST_NOT_IMPLEMENTED;
	tc->logcount = 0;
	tc->info = NULL;
	return AMVP_SUCCESS;
}

AMVP_RESULT state(AMVP_TEST_CASE *tc, const char *args, const char *info)
{
   return not_implemented_yet(tc);
}

AMVP_RESULT finite_state_machine(AMVP_TEST_CASE *tc)
{
   return not_implemented_yet(tc);
}
   
AMVP_RESULT self_test_verify(AMVP_TEST_CASE *tc);
{
   return not_implemented_yet(tc);
}

AMVP_RESULT csp_protection(AMVP_TEST_CASE *tc);
{
   return not_implemented_yet(tc);
}

AMVP_RESULT zeroize_test(AMVP_TEST_CASE *tc);
{
   return not_implemented_yet(tc);
}

AMVP_RESULT pk11_mode(AMVP_TEST_CASE *tc, const char *args, const char *info)
{
   return not_implemented_yet(tc);
}

AMVP_RESULT pk11_mode_error(AMVP_TEST_CASE *tc, const char *args, const char *info)
{
   return not_implemented_yet(tc);
}

AMVP_RESULT pk11_mode_log(AMVP_TEST_CASE *tc, const char *args, const char *info)
{
   return not_implemented_yet(tc);
}


amvp_handle_test(AMVP_TEST_CASE tc)
{
   switch (tc->test_type) {
   case TE01_03_02:
	return pk11_mode(tc, "-F -v", "See FIPS MODE and Hybrid MODE");
   case TE01_04_02:
	return pk11_mode(tc, "-F -v", "See FIPS MODE and Hybrid MODE");
   case TE02_06_02:
	return state(tc, "-F -v", "xxxx");
   case TE02_06_04:
	return state(tc, "-F -v", "All inputs and outputs are tested");
   case TE02_13_03:
	return does_not_apply(tc, "Hardware only");
   case TE02_14_02:
	return pk11_mode(tc, "-F -v", "NSS never outputs CSPS");
   case TE03_02_02:
	return pk11_mode(tc, "-F -v", "NSS has only one operator");
   case TE03_11_02:
	return pk11_mode(tc, "-F -v", "See return codes and status function");
   case TE03_11_03:
	return pk11_mode_log(tc, "-F -v", "See audit log"); /* grab syslog */
   case TE03_03_02:
	return does_not_apply(tc, "NSS does not support bypass");
   case TE03_14_02:
   case TE03_15_02:
	return pk11_mode(tc, "-F -v", 
		"Crypto officer login for Initing database pasword,"
		" user logged in for other access");
   case TE03_17_02:
	return pk11_mode("tc, -F -v", "see C_Login tests");
   case TE03_18_02:
	return pk11_mode(tc, "-F -v", 
		"Crypto officer login for Initing database pasword,"
		" user logged in for other access");
   case TE03_21_02:
	return does_not_apply(tc, "Hardware only");
   case TE03_22_02:
	 /* create a database with a password */
	 /* change the database password */
	 /* access the database with old password, expect failure */
	 return certutil_db(tc); 
   case TE03_23_02:
	return pk11_mode(tc, "-F -v", "see C_Login tests");
   case TE03_24_02:
	return pk11_mode(tc, "-F -v", "see C_Login tests");
   case TE04_03_01:
	/* testing error states */
	return pk11_mode_error(tc, "-F -v","program should fail do to errors");
   case TE04_05_08:
	return finite_state_machine(tc);
   case TE07_01_02:
   case TE07_02_02:
	return csp_protection(tc);
   case TE07_15_02:
   case TE07_15_03:
   case TE07_15_04:
	return does_not_apply(tc, 
			"NSS does not provide intermediate key output");
   case TE07_23_03:
	return does_not_apply(tc, "NSS does not provide use seed keys");
   case TE07_25_02:
	return does_not_apply(tc, "NSS only supports one entity");
   case TE07_27_02:
   case TE07_29_02:
   case TE07_32_02:
	return does_not_apply(tc, 
			"NSS does not support an external display device");
   case TE07_39_02:
	return pk11_mode(tc, "-F -v", 
		"Crypto officer login for Initing database pasword,"
		" user logged in for other access");
   case TE07_41_02:
	return zeroize_test(tc);
   case TE09_04_03:
   case TE09_05_03:
   case TE09_06_02:
   case TE09_07_03:
   case TE09_09_02:
   case TE09_10_02:
   case TE09_12_02:
   case TE09_16_01:
   case TE09_16_02:
   case TE09_19_03:
   case TE09_22_07:
   case TE09_24_01:
   case TE09_27_01:
   case TE09_27_02:
   case TE09_31_01:
	return self_test_verify(tc);
   case TE09_35_04:
   case TE09_35_05:
	return does_not_apply(tc, "NSS does not load firmware");
   default:
	break;
   }
   return unknown_test();
}

