/********************************************************************************/
/*										*/
/*		    TPM public key TPM2B_PUBLIC to PEM 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpm2pem.c 826 2016-11-18 14:47:10Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* Converts a TPM public key TPM2B_PUBLIC to PEM */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

/* #include <tss2/tss.h> */
#include <tss2/tsserror.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/Unmarshal_fp.h>

static TPM_RC RSAGeneratePublicToken(RSA **rsa_pub_key,
				     unsigned char *narr,
				     uint32_t nbytes,
				     unsigned char *earr,
				     uint32_t ebytes);
static TPM_RC bin2bn(BIGNUM **bn, const unsigned char *bin, unsigned int bytes);
static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				irc;
    int				i;    /* argc iterator */
    const char			*publicKeyFilename = NULL;
    EVP_PKEY 			*pkey = NULL;          	/* OpenSSL public key, EVP format */
    const char			*pemFilename = NULL;
    FILE 			*pemFile = NULL; 
    TPM2B_PUBLIC 		public;
    RSA         		*rsa_pub_key = NULL;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ipu") == 0) {
	    i++;
	    if (i < argc) {
		publicKeyFilename = argv[i];
	    }
	    else {
		printf("-ipu option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-opem") == 0) {
	    i++;
	    if (i < argc) {
		pemFilename = argv[i];
	    }
	    else {
		printf("-ipem option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    verbose = TRUE;
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (publicKeyFilename == NULL) {
	printf("Missing private key parameter -ipu\n");
	printUsage();
    }
    /* read the TPM public key to a structure */
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&public,
				    (UnmarshalFunction_t)TPM2B_PUBLIC_Unmarshal,
				    publicKeyFilename);
    }
    /* construct the OpenSSL RSA public key object */
    if (rc == 0) {
	unsigned char earr[3] = {0x01, 0x00, 0x01};
	rc = RSAGeneratePublicToken(&rsa_pub_key,				/* freed @1 */
				    public.publicArea.unique.rsa.t.buffer, /* public modulus */
				    public.publicArea.unique.rsa.t.size,
				    earr,      				/* public exponent */
				    sizeof(earr));
    }
    /* convert to openssl EVP object */
    if (rc == 0) {
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
	    printf("RSAVerifyPEM: EVP_PKEY failed\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc  = EVP_PKEY_assign_RSA(pkey, rsa_pub_key);
	if (irc == 0) {
	    printf("RSAVerifyPEM: EVP_PKEY_assign_RSA failed\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
	    
    }
    /* write the openssl RSA structure in PEM format */
    if (rc == 0) {
	pemFile = fopen(pemFilename, "wb");
	if (pemFile == NULL) {
	    printf("main: Unable to open PEM file %s for write\n", pemFilename);
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    if (rc == 0) {
	irc = PEM_write_PUBKEY(pemFile, pkey);
	if (irc == 0) {
	    printf("main: Unable to write PEM file %s\n", pemFilename);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    if (rc == 0) {
	if (verbose) printf("tpm2pem: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("tpm2pem: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    if (pkey != NULL) {
	EVP_PKEY_free(pkey);
	pkey = NULL;
    }
    /* since EVP_PKEY_free appears to free the RSA key token, add this so this call always frees the
       token, even on error */
    else {
	if (rsa_pub_key != NULL) {
	    RSA_free(rsa_pub_key);          /* @1 */
	}
    }
    if (pemFile != NULL) {
	fclose(pemFile);
	pemFile = NULL;
    }
    return rc;
}

/* TSS_RSAGeneratePublicToken() generates an RSA key token from n and e
 */

static TPM_RC RSAGeneratePublicToken(RSA **rsa_pub_key,		/* freed by caller */
				     unsigned char *narr,      	/* public modulus */
				     uint32_t nbytes,
				     unsigned char *earr,      	/* public exponent */
				     uint32_t ebytes)
{
    TPM_RC  	rc = 0;
    BIGNUM *    n = NULL;
    BIGNUM *    e = NULL;

    /* sanity check for the free */
    if (rc == 0) {
	if (*rsa_pub_key != NULL) {
            if (verbose)
		printf("RSAGeneratePublicToken: Error (fatal), token %p should be NULL\n",
		       *rsa_pub_key );
            rc = TSS_RC_ALLOC_INPUT;
	}
    }
    /* construct the OpenSSL private key object */
    if (rc == 0) {
        *rsa_pub_key = RSA_new();                        	/* freed by caller */
        if (*rsa_pub_key == NULL) {
            if (verbose) printf("RSAGeneratePublicToken: Error in RSA_new()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
        }
    }
    if (rc == 0) {
        rc = bin2bn(&n, narr, nbytes);	/* freed by caller */
    }
    if (rc == 0) {
        (*rsa_pub_key)->n = n;
        rc = bin2bn(&e, earr, ebytes);	/* freed by caller */
    }
    if (rc == 0) {
        (*rsa_pub_key)->e = e;
        (*rsa_pub_key)->d = NULL;
    }
    return rc;
}

/* bin2bn() wraps the openSSL function in a TPM error handler

   Converts a char array to bignum

   bn must be freed by the caller.
*/

static TPM_RC bin2bn(BIGNUM **bn, const unsigned char *bin, unsigned int bytes)
{
    TPM_RC	rc = 0;

    /* BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
    
       BN_bin2bn() converts the positive integer in big-endian form of length len at s into a BIGNUM
       and places it in ret. If ret is NULL, a new BIGNUM is created.

       BN_bin2bn() returns the BIGNUM, NULL on error.
    */
    if (rc == 0) {
        *bn = BN_bin2bn(bin, bytes, *bn);
        if (*bn == NULL) {
            printf("bin2bn: Error in BN_bin2bn\n");
            rc = TSS_RC_BIGNUM;
        }
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("tpm2pem\n");
    printf("\n");
    printf("Converts a TPM2B_PUBLIC to PEM\n");
    printf("\n");
    printf("\t-ipu public key file name in TPM format\n");
    printf("\t-opem public key PEM format file name\n");
    exit(1);	
}
