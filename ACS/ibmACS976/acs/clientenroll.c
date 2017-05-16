/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client Side Enrollment			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: clientenroll.c 950 2017-03-02 22:11:02Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016, 2017					*/
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

/*  The overall steps are:

    Create an attestation key.
    Send the attestation key and EK certificate to the server
    Activate credential on the attestation key certificate
    Send the attestation key certificate back to the server.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/pem.h>
#include <openssl/err.h>

#include <json/json.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssfile.h>
#include <tss2/tssprint.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>
#include "ekutils.h"

#include "config.h"
#include "clientjson.h"
#include "commonjson.h"
#include "clientsocket.h"
#include "commonutils.h"
#include "commoncrypto.h"
#include "commontss.h"
#include "commonerror.h"
#include "clientlocal.h"

/* local function prototypes */

static void printUsage(void);

static TPM_RC sendEnrollRequest(json_object **enrollResponseJson,
				const char *hostname,
				short port,
				const char *machineName,
				const char *tpmVendor,
				uint32_t ekCertLength,
				unsigned char *ekCertificate,
				uint16_t attestPubLength,
				unsigned char *attestPub);
static TPM_RC validateCertificate(unsigned char *certificateBin,
				  uint32_t certificateBinLen);
static TPM_RC processEnrollResponse(json_object **enrollCertResponseJson,
				    const char *certificateFilename,
				    const char *hostname,
				    short port,
				    const char *machineName,
				    TPM2B_PRIVATE *attestPriv,
				    TPM2B_PUBLIC *attestPub,
				    TPMI_RH_NV_INDEX ekCertIndex,
				    json_object *enrollResponseJson);
int verbose = 0;
int vverbose = 0;
#ifdef TPM_ACS_PVM_REMOTE
char  g_sphost[100] = ""; 	/* Service processor hostname */
short g_spport = 30015; 	/* Attestation port on service processor */
#endif

int main(int argc, char *argv[])
{
    int 		rc = 0;
    int			i;    /* argc iterator */
    /* command line argument defaults */
    TPMI_RH_NV_INDEX	ekCertIndex = EK_CERT_RSA_INDEX;	/* default RSA */
    const char 		*hostname = "localhost";	/* default server */
    const char 		*portString = NULL; 		/* server port */
    short 		port = 2323;			/* default server */
    const char          *machineName = NULL;		/* default use gethostname() */
    const char 		*certificateFilename = NULL;	/* default no AK certificate output */
    int			requestOnly = 0;		/* for server debug */
    const char 		*akpubFilename = AK_RSA_PUB_FILENAME;	/* default RSA */
    const char 		*akprivFilename = AK_RSA_PRIV_FILENAME;	/* default RSA */
    
    
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms();
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1"); /* default traces TSS errors */
    /* get the socket port number as a string */
    portString = getenv("ACS_PORT");
    if (portString != NULL) {
        sscanf(portString , "%hu", &port);
    }
    /* parse command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-alg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"rsa") == 0) {
		    ekCertIndex = EK_CERT_RSA_INDEX;
		    akpubFilename = AK_RSA_PUB_FILENAME;
		    akprivFilename = AK_RSA_PRIV_FILENAME;
		}
		else if (strcmp(argv[i],"ec") == 0) {
		    ekCertIndex = EK_CERT_EC_INDEX;
		    akpubFilename = AK_EC_PUB_FILENAME;
		    akprivFilename = AK_EC_PRIV_FILENAME;
		}
		else {
		    printf("Bad parameter for -alg\n");
		    printUsage();
		}
	    }
	    else {
		printf("-alg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ho") == 0) {
	    i++;
	    if (i < argc) {
		hostname = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -ho\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-po") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i], "%hu", &port);
	    }
	    else {
		printf("ERROR: Missing parameter for -po\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ma") == 0) {
	    i++;
	    if (i < argc) {
		machineName = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -ma\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-co") == 0) {
	    i++;
	    if (i < argc) {
		certificateFilename = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -co\n");
		printUsage();
	    }
	    
	}
	else if (strcmp(argv[i],"-ro") == 0) {
	    requestOnly = 1;
	}
#ifdef TPM_ACS_PVM_REMOTE
	else if (strcmp(argv[i], "-sphost") == 0) {
	    i++;
	    if (i < argc) {
		strncpy(g_sphost, argv[i], sizeof(g_sphost));
		g_sphost[sizeof(g_sphost)-1] = '\0';
	    }
	    else {
		printf("ERROR: Missing parameter for -sphost\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-spport") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i], "%hu", &g_spport);
	    }
	    else {
		printf("ERROR: Missing parameter for -spport\n");
		printUsage();
	    }
	}
#endif        
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    verbose = 1;
	}
	else if (strcmp(argv[i],"-vv") == 0) {
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");	/* trace entire TSS */
	    verbose = 1;
	    vverbose = 1;
	}
	else {
 	    printf("\nERROR: %s is not a valid option\n", argv[i]);
	    /* printUsage(); */
	}
    }
#ifdef TPM_ACS_PVM_REMOTE
    if (strlen(g_sphost) == 0) {
        printf("\nERROR: Missing -sphost\n");
        printUsage();
    }
#endif
    /* Create the enrollment data */
    char 		tpmVendor[5];
    uint16_t 		ekCertLength;
    unsigned char 	*ekCertificate = NULL;			/* freed @3 */	
    TPM2B_PRIVATE 	attestPriv;
    TPM2B_PUBLIC 	attestPub;				/* marshalled TPMT_PUBLIC */
    uint16_t 		attestPubLength;
    unsigned char 	*attestPubBin = NULL;			/* freed @4 */
    
    if (rc == 0) {
	rc = createEnrollmentData(tpmVendor,
				  &ekCertLength, &ekCertificate,	/* freed @3 */		
				  &attestPriv, &attestPub,
				  &attestPubLength, &attestPubBin,	/* freed @4 */
				  ekCertIndex);
    }
    /* send the enrollment data to the server */ 
    json_object *enrollResponseJson = NULL;
    if (rc == 0) {
	rc = sendEnrollRequest(&enrollResponseJson,		/* freed @1 */
			       hostname,
			       port,
			       machineName,
			       tpmVendor,
			       ekCertLength, ekCertificate,
			       attestPubLength, attestPubBin);
    }
    /* Activate credential on the attestation key certificate. Send the attestation key certificate
       back to the server.  Process the ACK from the server. */
    json_object *enrollCertResponseJson = NULL;
    if ((rc == 0) && !requestOnly) {
	rc = processEnrollResponse(&enrollCertResponseJson,	/* freed @2 */
				   certificateFilename,
				   hostname,
				   port,
				   machineName,
				   &attestPriv, &attestPub,
				   ekCertIndex,
				   enrollResponseJson);
    }
    /* if enrollment is successful, save the private key */
    if ((rc == 0) && !requestOnly) {
	rc = TSS_File_WriteStructure(&attestPriv,
				     (MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshal,
				     akprivFilename);
    }
    /* if enrollment is successful, save the public key */
    if ((rc == 0) && !requestOnly) {
	rc = TSS_File_WriteStructure(&attestPub,
				     (MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshal,
				     akpubFilename);
    }
    JS_ObjectFree(enrollResponseJson);		/* @1 */
    JS_ObjectFree(enrollCertResponseJson);	/* @2 */
    free(ekCertificate);			/* @3 */
    free(attestPubBin);				/* @4 */
    return rc;
}

/* sendEnrollRequest() sends a request of the form:

   {
   "command":"enrollrequest",
   "hostname":"name",
   "tpmvendor":vendor",
   "ekcert":"hexascii",
   "public":"hexascii"
   }
*/

static TPM_RC sendEnrollRequest(json_object **enrollResponseJson,	/* freed by caller */
				const char *hostname,
				short port,
				const char *machineName,
				const char *tpmVendor,
				uint32_t ekCertLength,
				unsigned char *ekCertificate,		/* EK certificate */
				uint16_t attestPubLength,
				unsigned char *attestPub)		/* Attestation public key */
{
    TPM_RC 		rc = 0;
    uint32_t 		cmdLength;
    uint8_t 		*cmdBuffer = NULL;			/* freed @1 */
    uint32_t 		rspLength;
    uint8_t 		*rspBuffer = NULL;			/* freed @2 */
    char		*ekCertificateString = NULL;
    char		*attestPubString = NULL;

    if (vverbose) printf("INFO: sendEnrollRequest\n");
    /* convert the EK certificate to string */
    if (rc == 0) {
	rc = Array_PrintMalloc(&ekCertificateString,		/* freed @3 */
			       ekCertificate,
			       ekCertLength);
    }
    /* convert the EK certificate to string */
    if (rc == 0) {
	rc = Array_PrintMalloc(&attestPubString,		/* freed @4 */
			       attestPub,
			       attestPubLength);
    }
    /* construct the enrollment request command packet */
    if (rc == 0) {
	rc = JS_Cmd_EnrollRequest(&cmdLength,
				  (char **)&cmdBuffer,		/* freed @1 */
				  tpmVendor,
				  ekCertificateString,
				  attestPubString,
				  machineName);
    }
    /* send the json command and receive the response */
    if (rc == 0) {
	rc = Socket_Process(&rspBuffer, &rspLength,		/* freed @2 */
			    hostname, port,
			    cmdBuffer, cmdLength);
    }
    /* parse json stream response to object */
    if (rc == 0) {
	rc = JS_ObjectUnmarshal(enrollResponseJson,	/* freed by caller */
				rspBuffer);
    }
    /* for debug */
    if (rc == 0) {
	if (verbose) JS_ObjectTrace("INFO: sendEnrollRequest: response", *enrollResponseJson);
    }
    free(cmdBuffer);		/* @1 */
    free(rspBuffer);		/* @2 */
    free(ekCertificateString);	/* @3 */
    free(attestPubString);	/* @4 */
    return rc;
}

/* processEnrollResponse() gets a server response of the form

   {
   "response":"enrollrequest",
   "enccert":"hexascii",   
   "credentialblob":"hexascii",
   "secret":"hexascii"
   }

   It sends a request of the form:
   {
   "command":"enrollcert",
   "hostname":"cainl.watson.ibm.com",
   "akcert":"hexascii",
   }
*/

static TPM_RC processEnrollResponse(json_object **enrollCertResponseJson,
				    const char *certificateFilename,
				    const char *hostname,
				    short port,
				    const char *machineName,
				    TPM2B_PRIVATE *attestPriv,
				    TPM2B_PUBLIC *attestPub,
				    TPMI_RH_NV_INDEX ekCertIndex,
				    json_object *enrollResponseJson)
{
    TPM_RC 		rc = 0;
    uint32_t 		cmdLength;
    uint8_t 		*cmdBuffer = NULL;		/* freed @1 */
    uint32_t 		rspLength;
    uint8_t 		*rspBuffer = NULL;		/* freed @2 */

    if (vverbose) printf("INFO: processEnrollResponse: Entry\n");
    /* FIXME check for error response */
    const char *response = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&response, "response", enrollResponseJson);
    }
    /* get the encrypted certificate */
    const char *encCert = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&encCert, "enccert", enrollResponseJson);
    }
    /* get the encrypted certificate */
    const char *credentialBlob = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&credentialBlob, "credentialblob", enrollResponseJson);
    }
    /* get the encrypted certificate */
    const char *secret = NULL;
    if (rc == 0) {
	rc = JS_ObjectGetString(&secret, "secret", enrollResponseJson);
    }
    /* convert the enccert to binary */
    unsigned char 	*encCertBin = NULL;
    size_t 		encCertBinSize;
    if (rc == 0) {
	rc = Array_Scan(&encCertBin,	/* output binary, freed @3 */
			&encCertBinSize,
			encCert);	/* input string */
    }    
    /* convert the credentialblob to binary */
    unsigned char 	*credentialBlobBin = NULL;
    size_t 		credentialBlobBinSize;
    if (rc == 0) {
	rc = Array_Scan(&credentialBlobBin,	/* output binary, freed @4 */
			&credentialBlobBinSize,
			credentialBlob);	/* input string */
    }    
    /* convert the secret to binary */
    unsigned char 	*secretBin = NULL;
    size_t 		secretBinSize;
    if (rc == 0) {
	rc = Array_Scan(&secretBin,	/* output binary, freed @5 */
			&secretBinSize,
			secret);	/* input string */
    }
    TPM2B_DIGEST certInfo;	/* the symmetric key */
    if (rc == 0) {
	rc = recoverAttestationKeyCertificate(&certInfo,	/* recovered key */
					      attestPriv,
					      attestPub,
					      ekCertIndex,
					      credentialBlobBin,
					      credentialBlobBinSize,
					      secretBin,
					      secretBinSize);
    }
    if (rc == 0) {
	if (verbose) printf("INFO: processEnrollResponse: Recovered AES key\n");
#if 0
	if (vverbose) TSS_PrintAll("processEnrollResponse: Encrypted certificate:",
				   encCertBin, encCertBinSize);
#endif
    }
    /* decrypt the attestation certificate with the recovered symmetric key */
    unsigned char *certificateBin = NULL;	/* decrypted certificate in DER format */
    uint32_t certificateBinLen;
    if (rc == 0) {
	rc = aesdecrypt(&certificateBin,   	/* output decrypted data, caller frees */
			&certificateBinLen,
			encCertBin,		/* input encrypted data */
			encCertBinSize,		/* input */
			&certInfo);		/* decryption symmetric key */

    }
#if 0
    if (rc == 0) {
	if (vverbose) TSS_PrintAll("processEnrollResponse: Certificate:",
				   certificateBin, certificateBinLen);
    }
#endif
    if (rc == 0) {
	X509 *ekX509Certificate = NULL;
	unsigned char *tmpCert = certificateBin;	/* temp because d2i moves the pointer */
	ekX509Certificate = d2i_X509(NULL,		/* freed @2 */
				     (const unsigned char **)&tmpCert,certificateBinLen);
	if (ekX509Certificate == NULL) {
	    printf("ERROR: processEnrollResponse: Could not parse X509 EK certificate\n");
	    rc = ACE_INVALID_CERT;
	}
	else {
	    if (vverbose) X509_print_fp(stdout, ekX509Certificate );
	}
	if (ekX509Certificate != NULL) {
	    X509_free(ekX509Certificate);   /* @2 */
	}
    }
    if ((rc == 0) && (certificateFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(certificateBin,
				      certificateBinLen,
				      certificateFilename);
    }
    /* convert the DER certificate to hexascii to send back to server */
    char		*certificateString = NULL;
    if (rc == 0) {
	rc = Array_PrintMalloc(&certificateString,		/* freed @9 */
			       certificateBin,
			       certificateBinLen);
    }
    /* sanity check, validate the certificate against the privacy CA certificate */
    if (rc == 0) {
	rc  = validateCertificate(certificateBin,
				  certificateBinLen);
    }
    /* construct the enrollment certificate command packet */
    /* converts the EK certificate to string */
    if (rc == 0) {
	rc = JS_Cmd_EnrollCert(&cmdLength,
			       (char **)&cmdBuffer,
			       certificateString,
			       machineName);
    }
    /* send the attestation certificate to the server */
    /* send the json command and receive the response */
    if (rc == 0) {
	rc = Socket_Process(&rspBuffer, &rspLength,	/* freed @2 */
			    hostname, port,
			    cmdBuffer, cmdLength);
    }
    /* parse json stream response to object */
    if (rc == 0) {
	rc = JS_ObjectUnmarshal(enrollCertResponseJson,	/* freed by caller */
				rspBuffer);
    }
    /* for debug */
    if (rc == 0) {
	if (verbose) JS_ObjectTrace("INFO: processEnrollResponse: response",
				    *enrollCertResponseJson);
    }
    /* cleanup */
    free(cmdBuffer);		/* @1 */
    free(rspBuffer);		/* @2 */
    free(encCertBin);		/* @3 */
    free(credentialBlobBin);	/* @4 */
    free(secretBin);		/* @5 */
    free(certificateString);	/* @9 */
    return rc;
}

static TPM_RC validateCertificate(unsigned char *certificateBin,
				  uint32_t certificateBinLen)
{
    TPM_RC			rc = 0;

    /* unmarshal the AK certificate DER stream to AK certificate X509 structure */
    X509 *akX509Certificate = NULL;
    if (rc == 0) {
	unsigned char *tmpCert = certificateBin;	/* temp because d2i moves the pointer */
	akX509Certificate = d2i_X509(NULL,		/* freed @1 */
				     (const unsigned char **)&tmpCert, certificateBinLen);
	if (akX509Certificate == NULL) {
	    printf("ERROR: validateCertificate: Could not parse X509 EK certificate\n");
	    rc = ACE_INVALID_CERT;
	}
    }
    /*
      construct the privacy CA root certificate store
    */
    X509_STORE 		*caStore = NULL;	/* freed @2 */
    if (rc == 0) {
	caStore  = X509_STORE_new();		/* freed @2 */
	if (caStore == NULL) {
	    printf("validateCertificate: X509_store_new failed\n");  
	    rc = ACE_OUT_OF_MEMORY;
	}
    }
    /* read a root certificate from the file */
    FILE *caCertFile = NULL;			/* closed @3 */
    if (rc == 0) {
	caCertFile = fopen(PCA_CERT, "rb");	/* closed @3 */
	if (caCertFile == NULL) {
	    printf("validateCertificate: Error opening CA root certificate file %s\n", PCA_CERT);  
	    rc = ACE_FILE_OPEN;
	}
    }
    /* convert the root certificate from PEM to X509 */
    X509 	*caCert = NULL;
    if (rc == 0) {
	caCert = PEM_read_X509(caCertFile, NULL, 0, NULL);	/* freed @4 */
	if (caCert == NULL) {
	    printf("validateCertificate: Error reading CA root certificate file %s\n",
		   PCA_CERT);  
	    rc = ACE_FILE_READ;
	} 
    }
    /* add the CA X509 certificate to the certificate store */
    if (rc == 0) {
	X509_STORE_add_cert(caStore, caCert);    
    }
    X509_STORE_CTX 		*verifyCtx = NULL;		/* freed @5 */
    /* create the certificate verify context */
    if (rc == 0) {
	verifyCtx = X509_STORE_CTX_new();
	if (verifyCtx == NULL) {
	    printf("ERROR: validateCertificate: X509_STORE_CTX_new failed\n");  
	    rc = ACE_OUT_OF_MEMORY;
	}
    }
    /* add the root CA certificate store and AK certificate to be verified to the verify context */
    if (rc == 0) {
	int irc = X509_STORE_CTX_init(verifyCtx, caStore, akX509Certificate, NULL);
	if (irc != 1) {
	    printf("ERROR: validateEkCertificate: "
		   "Error in X509_STORE_CTX_init initializing verify context\n");  
	    rc = ACE_OSSL_X509;
	}	    
    }
    /* walk the TPM AK certificate chain */
    if (rc == 0) {
	int irc = X509_verify_cert(verifyCtx);
	if (irc != 1) {
	    printf("ERROR: validateCertificate: "
		   "Error in X590_verify_cert verifying certificate\n");  
	    rc = ACE_INVALID_CERT;
	}
	else {
	    if (verbose) printf("INFO: validateCertificate: "
				"AK certificate verified against the PCA root\n");
	}
    }
    if (akX509Certificate != NULL) {
	X509_free(akX509Certificate);   /* @1 */
    }
    if (caStore != NULL) {
	X509_STORE_free(caStore);	/* @2 */
    }
    if (caCertFile != NULL) {
	fclose(caCertFile);		/* @3 */
    }
    if (caCert != NULL) {
	X509_free(caCert);	   	/* @4 */
    }
    if (verifyCtx != NULL) {
	X509_STORE_CTX_free(verifyCtx);	/* @5 */
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("clientenroll\n");
    printf("\n");
    printf("Provisions an attestation client with an attestation key.\n"
	   "Obtains a certificate from the attestation server.\n");
    printf("\n");
    printf("[-alg (rsa or ec) (default rsa)]\n");
    printf("[-ho ACS server host name (default localhost)]\n");
    printf("[-po ACS server host port (default ACS_PORT or 2323)]\n");
    printf("[-ma Client machine name (default gethostname()]\n");
    printf("[-co AK certificate output file name]\n");
    printf("[-ro Request only, for debug]\n");
#ifdef TPM_ACS_PVM_REMOTE
    printf("[-sphost System service processor hostname]\n");
    printf("[-spport System service processor attestation port (default 30015)\n");
#endif
    printf("\n");
    printf("Currently hard coded:\n");
    printf("\n");
    printf("\tAttestation key file name is ak{alg}priv.bin/ak{alg}pub.bin\n");
    printf("\tEndorsement hierarchy authorization assumes Empty Auth\n");
    printf("\n");
    exit(1);	
}
