
/*
 * Since we're using JIT Trust, we don't need explict CA trust for this.
 */

/*
 * Which http protocol the content and OTA streams use.  h2 if it's built,
 * else h3 if that's built, else plain h1... a board CMakeLists that turns off
 * LWS_WITH_HTTP2 and leaves LWS_WITH_HTTP3 on therefore gets QUIC for these
 * without needing its own copy of the policy.  Can be overridden by defining
 * LHP_SS_PROTOCOL to eg, "h1" on the build commandline.
 *
 * The captive_portal_detect stream below is always h1, it's cleartext on
 * port 80 by nature.
 */

#if !defined(LHP_SS_PROTOCOL)
#if defined(LWS_ROLE_H2)
#define LHP_SS_PROTOCOL "h2"
#elif defined(LWS_ROLE_H3)
#define LHP_SS_PROTOCOL "h3"
#else
#define LHP_SS_PROTOCOL "h1"
#endif
#endif

static const char * const ss_policy =
	"{"
	  "\"release\":"			"\"01234567\","
	  "\"product\":"			"\"myproduct\","
	  "\"schema-version\":"			"1,"

	  "\"retry\": ["	/* named backoff / retry strategies */
		"{\"default\": {"
			"\"backoff\": ["	 "1000,"
						 "2000,"
						 "3000,"
						 "5000,"
						"10000"
				"],"
			"\"conceal\":"		"25,"
			"\"jitterpc\":"		"20,"
			"\"svalidping\":"	"30,"
			"\"svalidhup\":"	"35"
		"}}"
	  "],"
	  "\"s\": ["

		"{\"__default\": {"
			"\"endpoint\":"		"\"${endpoint}\","
			"\"port\":"		"443,"
			"\"protocol\":"		"\"" LHP_SS_PROTOCOL "\","
			"\"http_method\":"	"\"GET\","
			"\"http_url\":"		"\"\","
			"\"metadata\": [{\n"
				"\"endpoint\":"      "\"\",\n"
				"\"acc\":"      "\"accept\",\n"
				"\"ua\":"	"\"user-agent\"\n"
			"}],\n"
			"\"tls\":"		"true,"
			"\"allow_redirects\": true,\n"
			"\"nghttp2_quirk_end_stream\": true,\n"
			"\"h2q_oflow_txcr\": true,\n"
			"\"opportunistic\":"	"true,"
			"\"retry\":"		"\"default\""

			"}},{\"ota\": {"
				"\"endpoint\":"		"\"libwebsockets.org\","
				"\"port\":"		"443,"
				"\"protocol\":"		"\"" LHP_SS_PROTOCOL "\","
				"\"http_method\":"	"\"GET\","
				"\"http_url\":"		"\"firmware/examples/${ota_variant}/${file}\","
				"\"metadata\": [{\n"
					"\"ota_variant\":"	"\"\",\n"
					"\"file\":"		"\"\"\n"
				"}],\n"
				"\"tls\":"		"true,"
				"\"allow_redirects\": true,\n"
				"\"nghttp2_quirk_end_stream\": true,\n"
				"\"h2q_oflow_txcr\":"	"true,\n"
				"\"opportunistic\":"	"true,"
				"\"retry\":"		"\"default\""
	
			"}},{"
			/*
			 * "captive_portal_detect" describes
			 * what to do in order to check if the path to
			 * the Internet is being interrupted by a
			 * captive portal.
			 */
		    "\"captive_portal_detect\": {"
                        "\"endpoint\":"		"\"connectivitycheck.android.com\","
			"\"http_url\":"		"\"generate_204\","
			"\"port\":"		"80,"
                        "\"protocol\":"		"\"h1\","
                        "\"http_method\":"	"\"GET\","
                        "\"opportunistic\":"	"true,"
                        "\"http_expect\":"	"204,"
			"\"http_fail_redirect\": true"
                "}}"
	"]}"
;


