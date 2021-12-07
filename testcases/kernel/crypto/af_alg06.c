// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2019 Google LLC
 */

/*
 * Regression test for commit 8f9c46934848 ("crypto: authenc - fix parsing key
 * with misaligned rta_len").  Based on the reproducer from the commit message.
 */

#include <errno.h>

#include "tst_test.h"
#include "tst_af_alg.h"
#include "lapi/socket.h"

/*
 * include after <sys/socket.h> (via tst_test.h), to work around dependency bug
 * in old kernel headers (https://www.spinics.net/lists/netdev/msg171764.html)
 */
#include <linux/rtnetlink.h>

static void test_with_symm_enc_algs(const char *symm_enc_algname)
{
	struct {
		struct rtattr attr;
		uint32_t enckeylen;
		char keys[1];
	} __attribute__((packed)) key = {
		.attr.rta_len = sizeof(key),
		.attr.rta_type = 1 /* CRYPTO_AUTHENC_KEYA_PARAM */,
	};
	int algfd;
	char authenc_algname[64];

	sprintf(authenc_algname, "authenc(hmac(sha256),cbc(%s))", symm_enc_algname);
	if (!tst_have_alg("aead", authenc_algname)) {
		tst_res(TCONF, "kernel doesn't have aead algorithm '%s'",
			authenc_algname);
		return;
	}

	algfd = tst_alg_setup("aead", authenc_algname, NULL, 0);
	tst_res(TINFO,
		"Setting malformed authenc key. May crash buggy kernels.");
	TEST(setsockopt(algfd, SOL_ALG, ALG_SET_KEY, &key, sizeof(key)));
	if (TST_RET == 0)
		tst_res(TFAIL, "setting malformed key unexpectedly succeeded");
	else if (TST_ERR != EINVAL)
		tst_res(TFAIL | TTERRNO,
			"setting malformed key failed with unexpected error");
	else
		tst_res(TPASS, "didn't crash, and got EINVAL as expected");
}

/* try several different symmetric encryption algorithms */
static const char * const symm_enc_algs[] = {
	"aes",
	"sm4",
};

static void do_test(unsigned int i)
{
	test_with_symm_enc_algs(symm_enc_algs[i]);
}

static struct tst_test test = {
	.test = do_test,
	.tcnt = ARRAY_SIZE(symm_enc_algs),
	.tags = (const struct tst_tag[]) {
		{"linux-git", "8f9c46934848"},
		{}
	}
};
