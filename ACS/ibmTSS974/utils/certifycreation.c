/********************************************************************************/
/*										*/
/*			    CertifyCreation					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: certifycreation.c 968 2017-03-17 19:05:04Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2017.						*/
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

/* 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>

static void printUsage(void);
static void printSignature(CertifyCreation_Out *out);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    CertifyCreation_In 		in;
    CertifyCreation_Out 	out;
    TPMI_DH_OBJECT		objectHandle = 0;
    TPMI_DH_OBJECT		signHandle = 0;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    const char			*keyPassword = NULL; 
    const char			*signatureFilename = NULL;
    const char			*attestInfoFilename = NULL;
    const char			*qualifyingDataFilename = NULL;
    const char			*ticketFilename = NULL;
    const char			*creationHashFilename = NULL;
    int				useRsa = 1;
    TPMS_ATTEST 		tpmsAttest;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ho") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&objectHandle);
	    }
	    else {
		printf("Missing parameter for -ho\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&signHandle);
	    }
	    else {
		printf("Missing parameter for -hk\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdk") == 0) {
	    i++;
	    if (i < argc) {
		keyPassword = argv[i];
	    }
	    else {
		printf("-pwdk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    halg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    halg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    halg = TPM_ALG_SHA384;
		}
		else {
		    printf("Bad parameter for -halg\n");
		    printUsage();
		}
	    }
	    else {
		printf("-halg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-salg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"rsa") == 0) {
		    useRsa = 1;
		}
		else if (strcmp(argv[i],"ecc") == 0) {
		    useRsa = 0;
		}
		else {
		    printf("Bad parameter for -salg\n");
		    printUsage();
		}
	    }
	    else {
		printf("-salg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-os") == 0) {
	    i++;
	    if (i < argc) {
		signatureFilename = argv[i];
	    }
	    else {
		printf("-os option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-oa") == 0) {
	    i++;
	    if (i < argc) {
		attestInfoFilename = argv[i];
	    }
	    else {
		printf("-oa option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-qd") == 0) {
	    i++;
	    if (i < argc) {
		qualifyingDataFilename = argv[i];
	    }
	    else {
		printf("-qd option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-tk") == 0) {
	    i++;
	    if (i < argc) {
		ticketFilename = argv[i];
	    }
	    else {
		printf("-tk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ch") == 0) {
	    i++;
	    if (i < argc) {
		creationHashFilename = argv[i];
	    }
	    else {
		printf("-ch option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se0") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle0);
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes0);
		if (sessionAttributes0 > 0xff) {
		    printf("Out of range session attributes for -se0\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se1") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle1);
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes1);
		if (sessionAttributes1 > 0xff) {
		    printf("Out of range session attributes for -se1\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se2") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle2);
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes2);
		if (sessionAttributes2 > 0xff) {
		    printf("Out of range session attributes for -se2\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	}
 	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    verbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (objectHandle == 0) {
	printf("Missing object handle parameter -ho\n");
	printUsage();
    }
    if (signHandle == 0) {
	printf("Missing sign handle parameter -hk\n");
	printUsage();
    }
    if (ticketFilename == NULL) {
	printf("Missing ticket parameter -tk\n");
	printUsage();
    }
    if (rc == 0) {
	/* Handle of key that will perform certifying */
	in.objectHandle = objectHandle;
	in.signHandle = signHandle;
	if (useRsa) {
	    /* Table 145 - Definition of TPMT_SIG_SCHEME Structure */
	    in.inScheme.scheme = TPM_ALG_RSASSA;	
	    /* Table 144 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */
	    /* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	    in.inScheme.details.rsassa.hashAlg = halg;
	}
	else {	/* ecc */
	    in.inScheme.scheme = TPM_ALG_ECDSA;	
	    in.inScheme.details.ecdsa.hashAlg = halg;
	}
    }
    /* qualifyingData supplied by the caller */
    if (rc == 0) {
	if (qualifyingDataFilename != NULL) {
	    rc = TSS_File_Read2B(&in.qualifyingData.b,
				 sizeof(TPMT_HA),
				 qualifyingDataFilename);
	}
	else {
	    in.qualifyingData.t.size = 0;
	}
    }
    /* creationTicket */
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&in.creationTicket,
				    (UnmarshalFunction_t)TPMT_TK_CREATION_Unmarshal,
				    ticketFilename);
    }
    /* creationHash */
    unsigned char 		*buffer = NULL;
    size_t 			length;
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&buffer ,     /* freed @1 */
				     &length,
				     creationHashFilename);
    }
    if (rc == 0) {
	if (length > sizeof(TPMU_HA)) {
	    printf("Size of creationHash %lu greater than hash size %lu\n",
		   (unsigned long)length, (unsigned long)sizeof(TPMU_HA));
	    rc = 1;	
	}
    }
    if (rc == 0) {
	in.creationHash.t.size = length;
	memcpy(in.creationHash.t.buffer, buffer, length);
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_CertifyCreation,
			 sessionHandle0, keyPassword, sessionAttributes0,
			 sessionHandle1, NULL, sessionAttributes1,
			 sessionHandle2, NULL, sessionAttributes2,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	uint8_t *tmpBuffer = out.certifyInfo.t.attestationData;
	int32_t tmpSize = out.certifyInfo.t.size;
	rc = TPMS_ATTEST_Unmarshal(&tpmsAttest, &tmpBuffer, &tmpSize);
    }
    if (rc == 0) {
	int match;
	match = TSS_TPM2B_Compare(&in.qualifyingData.b, &tpmsAttest.extraData.b);
	if (!match) {
	    printf("certifycreation: failed, extraData != qualifyingData\n");
	    rc = EXIT_FAILURE;
	}
    }
    if (rc == 0) {
	int match;
	match = TSS_TPM2B_Compare(&in.creationHash.b, &tpmsAttest.attested.creation.creationHash.b);
	if (!match) {
	    printf("certifycreation: failed, in creationHash != out creationHash\n");
	    rc = EXIT_FAILURE;
	}
    }
    if (rc == 0) {
	if (verbose) TSS_TPMS_ATTEST_Print(&tpmsAttest, 0);
    }
    if ((rc == 0) && (signatureFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.signature,
				     (MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshal,
				     signatureFilename);
    }
    if ((rc == 0) && (attestInfoFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.certifyInfo.t.attestationData,
				      out.certifyInfo.t.size,
				      attestInfoFilename);
    }
    if (rc == 0) {
	if (verbose) printSignature(&out);
	if (verbose) printf("certifycreation: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("certifycreation: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(buffer);	/* @1 */
    return rc;
}

static void printSignature(CertifyCreation_Out *out)
{
    TSS_PrintAll("Signature",
		 out->signature.signature.rsassa.sig.t.buffer,
		 out->signature.signature.rsassa.sig.t.size);
}

static void printUsage(void)
{
    printf("\n");
    printf("certify\n");
    printf("\n");
    printf("Runs TPM2_CertifyCreation\n");
    printf("\n");
    printf("\t-ho object handle\n");
    printf("\t-hk certifying key handle\n");
    printf("\t[-pwdk password for key (default empty)]\n");
    printf("\t[-halg [sha1, sha256, sha384] (default sha256)]\n");
    printf("\t[-salg signature algorithm [rsa, ecc] (default rsa)]\n");
    printf("\t[-qd qualifying data file name]\n");
    printf("\t-tk input ticket file name\n");
    printf("\t-ch input creation hash file name\n");
    printf("\t[-os signature file name]\n");
    printf("\t[-oa attestation output file name]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t\t01 continue\n");
    exit(1);	
}
