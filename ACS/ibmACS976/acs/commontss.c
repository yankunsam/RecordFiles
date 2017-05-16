/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Common TSS Functions	  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commontss.c 927 2017-01-26 14:42:59Z kgoldman $		*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssprint.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>

#include "ekutils.h"

#include "config.h"
#include "commontss.h"

extern int verbose;
extern int vverbose;

TPM_RC getTpmVendor(TSS_CONTEXT *tssContext,
		    char 	*tpmVendor)		/* 5 byte array */
{
    TPM_RC 			rc = 0;
    GetCapability_In 		in;
    GetCapability_Out		out;
    
    if (rc == 0) {
	in.capability = TPM_CAP_TPM_PROPERTIES;
	in.property = TPM_PT_MANUFACTURER;
	in.propertyCount = 1;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_GetCapability,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	tpmVendor[0] = (out.capabilityData.data.tpmProperties.tpmProperty[0].value >> 24) & 0xff;
	tpmVendor[1] = (out.capabilityData.data.tpmProperties.tpmProperty[0].value >> 16) & 0xff;
	tpmVendor[2] = (out.capabilityData.data.tpmProperties.tpmProperty[0].value >>  8) & 0xff;
	tpmVendor[3] = (out.capabilityData.data.tpmProperties.tpmProperty[0].value >>  0) & 0xff;
	tpmVendor[4] = '\0';
	if (vverbose) printf("INFO: getTpmVendor: %s\n", tpmVendor);
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: getTpmVendor: TPM2_GetCapability failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* getCapSrk() probes the TPM to determine if the SRK exists.

   Returns TRUE or FALSE.
*/

TPM_RC getCapSrk(TSS_CONTEXT 	*tssContext,
		 int   		*exists)
{
    TPM_RC 			rc = 0;
    GetCapability_In 		in;
    GetCapability_Out		out;

    if (rc == 0) {
	in.capability = TPM_CAP_HANDLES;
	in.property = TPM_HT_PERSISTENT << 24;
	in.propertyCount = 1;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_GetCapability,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	/* if the getcap returned the SRK handle */
	if ((out.capabilityData.data.handles.count > 0) &&
	    (out.capabilityData.data.handles.handle[0] == SRK_HANDLE)) {
	    *exists = TRUE;
	}
	else {
	    *exists = FALSE;
	}
	if (vverbose) printf("INFO: getCapSrk: TPM2_GetCapability exists %u\n",
			     *exists);
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: getCapSrk: TPM2_GetCapability failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* createSrk() creates a storage primary key in the owner hierarchy, returning the loaded transient
   key handle

*/

TPM_RC createSrk(TSS_CONTEXT 	*tssContext,
		 TPM_HANDLE 	*handle)
{
    TPM_RC			rc = 0;
    CreatePrimary_In 		in;
    CreatePrimary_Out 		out;
    
    /* set up the createprimary in parameters */
    if (rc == 0) {
	in.primaryHandle = TPM_RH_OWNER;
	in.inSensitive.sensitive.userAuth.t.size = 0;
	in.inSensitive.sensitive.data.t.size = 0;
	/* creation data */
	in.outsideInfo.t.size = 0;
	in.creationPCR.count = 0;
	in.inPublic.publicArea.type = TPM_ALG_RSA;
	in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	in.inPublic.publicArea.objectAttributes.val = TPMA_OBJECT_NODA |
							TPMA_OBJECT_FIXEDTPM |
							TPMA_OBJECT_FIXEDPARENT |
							TPMA_OBJECT_SENSITIVEDATAORIGIN |
							TPMA_OBJECT_USERWITHAUTH |
							TPMA_OBJECT_DECRYPT |
							TPMA_OBJECT_RESTRICTED;
	in.inPublic.publicArea.authPolicy.t.size = 0;
	in.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
	in.inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
	in.inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
	in.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	in.inPublic.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = 0;
	in.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
	in.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
	in.inPublic.publicArea.unique.rsa.t.size = 0;
	in.outsideInfo.t.size = 0;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_CreatePrimary,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
    }	
    if (rc == 0) {
	if (vverbose) printf("createSrk: Handle %08x\n", out.objectHandle);
	*handle  = out.objectHandle;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: createSrk: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
    }
    return rc;
}

/* persistSrk() makes a copy of the SRK in TPM non-volatile memory.  The transient copy is not
   flushed.

*/

TPM_RC persistSrk(TSS_CONTEXT 	*tssContext,
		  TPM_HANDLE 	srkHandle)
{
    TPM_RC			rc = 0;
    EvictControl_In 		in;

    if (rc == 0) {
	in.auth = TPM_RH_OWNER;
	in.objectHandle = srkHandle;
	in.persistentHandle = SRK_HANDLE;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_EvictControl,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc == 0) {
	    if (vverbose) printf("INFO: persistSrk: TPM2_EvictControl success\n");
	}
	else {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: evictcontrol: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    return rc;
}

/* createAttestationKey() creates the attestation signing key under the SRK parent.

   The key is not loaded.  The public and private parts are written to files.

   Returns the marshaled attestation signing key TPMT_PUBLIC.
*/

TPM_RC createAttestationKey(TSS_CONTEXT *tssContext,
			    TPMI_RH_NV_INDEX nvIndex,
			    TPM2B_PRIVATE *attestPriv,
			    TPM2B_PUBLIC *attestPub,
			    uint16_t *attestPubLength,
			    unsigned char **attestPubBin)	/* freed by caller */	
{
    TPM_RC 			rc = 0;
    Create_In 			in;
    Create_Out 			out;

    /* create the attestation key */
    if (rc == 0) {
	in.parentHandle = SRK_HANDLE;			/* under the SRK */
	in.inSensitive.sensitive.userAuth.t.size = 0;	/* password*/
	in.inSensitive.sensitive.data.t.size = 0;	/* no sealed data */

	in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	/* stClear is not set, so the attestation key context can be reloaded after a reboot */
	in.inPublic.publicArea.objectAttributes.val = TPMA_OBJECT_NODA |
						      TPMA_OBJECT_FIXEDTPM |
						      TPMA_OBJECT_FIXEDPARENT |
						      TPMA_OBJECT_SENSITIVEDATAORIGIN |
						      TPMA_OBJECT_USERWITHAUTH |
						      TPMA_OBJECT_SIGN |
						      TPMA_OBJECT_RESTRICTED;
	in.inPublic.publicArea.authPolicy.t.size = 0;
	if (nvIndex == EK_CERT_RSA_INDEX) {
	    in.inPublic.publicArea.type = TPM_ALG_RSA;
	    in.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	    in.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
	    in.inPublic.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg =
		TPM_ALG_SHA256;
	    in.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
	    in.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
	    in.inPublic.publicArea.unique.rsa.t.size = 0;
	}
	else if (nvIndex == EK_CERT_EC_INDEX) {
	    in.inPublic.publicArea.type = TPM_ALG_ECC;
	    in.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	    in.inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
		TPM_ALG_SHA256;
	    in.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
	    in.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
	    in.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	    in.inPublic.publicArea.unique.ecc.x.t.size = 0;
	    in.inPublic.publicArea.unique.ecc.y.t.size = 0;
	}
	else {
	    printf("ERROR: createAttestationKey unsupported algorithm\n");
	    rc = EXIT_FAILURE;
	}
	in.outsideInfo.t.size = 0;
	in.creationPCR.count = 0;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Create,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc == 0) {
	    if (vverbose) printf("INFO: createAttestationKey: TPM2_Create success\n");
	}
	else {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: createAttestationKey: TPM2_Create failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    /* return the attestation key public area */
    if (rc == 0) {
	rc = TSS_Structure_Marshal(attestPubBin,		/* freed by caller */
				   attestPubLength,
				   &out.outPublic.publicArea,
				   (MarshalFunction_t)TSS_TPMT_PUBLIC_Marshal);
    }
    /* return the attestation key structures */
    if (rc == 0) {
	*attestPriv = out.outPrivate;
	*attestPub = out.outPublic;
    }
    return rc;
}

/* loadAttestationKey() 

   Returns the loaded key handle.
*/

TPM_RC loadAttestationKey(TSS_CONTEXT 	*tssContext,
			  TPM_HANDLE 	*handle,
			  TPM2B_PRIVATE *attestPriv,
			  TPM2B_PUBLIC 	*attestPub)
{
    TPM_RC			rc = 0;
    Load_In 			in;
    Load_Out 			out;

    if (rc == 0) {
	in.parentHandle = SRK_HANDLE;
	in.inPrivate = *attestPriv;
	in.inPublic = *attestPub;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Load,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (vverbose) printf("loadAttestationKey: Handle %08x\n", out.objectHandle);
	*handle = out.objectHandle;
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("load: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* activatecredential() runs the TPM2_ActivateCredential() using the client TPM.

 */

TPM_RC activatecredential(TSS_CONTEXT *tssContext,
			  TPM2B_DIGEST *certInfo,
			  TPM_HANDLE activateHandle,		/* loaded key */
			  TPM_HANDLE keyHandle,			/* loaded EK */
			  unsigned char *credentialBlobBin,	/* marshaled */
			  size_t credentialBlobBinSize,
			  unsigned char *secretBin,		/* marshaled */
			  size_t secretBinSize)
{
    TPM_RC			rc = 0;
    ActivateCredential_In 	in;
    ActivateCredential_Out 	out;
    uint8_t 			*tmpptr;
    int32_t 			tmpsize;

    if (rc == 0) {
	in.activateHandle = activateHandle;
	in.keyHandle = keyHandle;
    }
    /* unmarshal the credential blob */
    if (rc == 0) {
	tmpptr = credentialBlobBin;
	tmpsize = credentialBlobBinSize;
	rc = TPM2B_ID_OBJECT_Unmarshal(&in.credentialBlob, &tmpptr, &tmpsize);
    }
    /* unmarshal the secret */
    if (rc == 0) {
	tmpptr = secretBin;
	tmpsize = secretBinSize;
	rc = TPM2B_ENCRYPTED_SECRET_Unmarshal(&in.secret, &tmpptr, &tmpsize);
    }
    /* using the EK requires a policy session */
    TPMI_SH_AUTH_SESSION 	sessionHandle;
    if (rc == 0) {
	rc = makePolicySession(tssContext,
			       &sessionHandle);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_ActivateCredential,
			 TPM_RS_PW, NULL, 0,
			 sessionHandle, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc == 0) {
	    *certInfo = out.certInfo;
	    if (vverbose) TSS_PrintAll("activatecredential: decrypted secret:",
				       out.certInfo.t.buffer, out.certInfo.t.size);
	}
	else {
	    flushContext(tssContext, sessionHandle);
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: activatecredential: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    return rc;
}
		
/* makePolicySession() makes a policy session that can be used as an EK authorization

   Returns the policy session handle.
*/

TPM_RC makePolicySession(TSS_CONTEXT *tssContext,
			 TPMI_SH_AUTH_SESSION *sessionHandle)
{
    TPM_RC 			rc = 0;
    StartAuthSession_In 	startAuthSessionIn;
    StartAuthSession_Out 	startAuthSessionOut;
    StartAuthSession_Extra	startAuthSessionExtra;
    PolicySecret_In 		policySecretIn;
    PolicySecret_Out 		policySecretOut;

    /* start a policy session */
    if (rc == 0) {
	startAuthSessionIn.sessionType = TPM_SE_POLICY;
	startAuthSessionIn.tpmKey = TPM_RH_NULL;
	startAuthSessionIn.bind = TPM_RH_NULL;
	startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
	startAuthSessionIn.authHash = TPM_ALG_SHA256;
	startAuthSessionIn.symmetric.keyBits.xorr = TPM_ALG_SHA256;
	startAuthSessionIn.symmetric.mode.sym = TPM_ALG_NULL;
	startAuthSessionExtra.bindPassword = NULL;
    }   
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&startAuthSessionOut, 
			 (COMMAND_PARAMETERS *)&startAuthSessionIn,
			 (EXTRA_PARAMETERS *)&startAuthSessionExtra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	*sessionHandle = startAuthSessionOut.sessionHandle;
	if (verbose) printf("INFO: makePolicySession: Policy session handle %08x\n",
			    startAuthSessionOut.sessionHandle);
	if (vverbose) printf("makePolicySession: TPM2_StartAuthSession success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: makePolicySession: TPM2_StartAuthSession failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    /* run policy secret over the endorsement auth to satisfy the policy */
    if (rc == 0) {
	policySecretIn.authHandle = TPM_RH_ENDORSEMENT;
	policySecretIn.policySession = startAuthSessionOut.sessionHandle;
	policySecretIn.nonceTPM.b.size = 0;
	policySecretIn.cpHashA.b.size = 0;
	policySecretIn.policyRef.b.size = 0;
	policySecretIn.expiration = 0;
    }   
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&policySecretOut, 
			 (COMMAND_PARAMETERS *)&policySecretIn,
			 NULL,
			 TPM_CC_PolicySecret,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (vverbose) printf("makePolicySession: TPM2_PolicySecret: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: makePolicySession: TPM2_PolicySecret: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* signQuote() signs a quote using the attestation keyHandle.

   It returns the quote data and signature.

*/

uint32_t signQuote(TSS_CONTEXT *tssContext,
		   TPM2B_ATTEST *quoted,
		   TPMT_SIGNATURE *signature,
		   TPM_HANDLE keyHandle,	/* attestation key */
		   TPMI_ALG_PUBLIC type,
		   const unsigned char *nonceBin,
		   size_t nonceLen,
		   const TPML_PCR_SELECTION *pcrSelection)
{
    TPM_RC			rc = 0;
    Quote_In 			in;
    Quote_Out 			out;
    
    if (rc == 0) {
	/* Handle of key that will perform quoting */
	in.signHandle = keyHandle;
	/* data supplied by the caller */
	/* FIXME should really come from AK public */
	if (type == TPM_ALG_RSA) {
	    /* Table 145 - Definition of TPMT_SIG_SCHEME Structure */
	    in.inScheme.scheme = TPM_ALG_RSASSA;	
	    /* Table 144 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */
	    /* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	    in.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
	}
	else if (type == TPM_ALG_ECC) {
	    in.inScheme.scheme = TPM_ALG_ECDSA;
	    in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
	}
	else {
	    printf("ERROR: signQuote: unsupported algorithm\n");
	    rc = EXIT_FAILURE;
	}
	/* Table 102 - Definition of TPML_PCR_SELECTION Structure */
	in.PCRselect.count = 1;
	/* Table 85 - Definition of TPMS_PCR_SELECTION Structure */
	in.PCRselect = *pcrSelection;
    }
    /* FIXME size check */
    if (rc == 0) {
	memcpy(in.qualifyingData.t.buffer, nonceBin, nonceLen);
	in.qualifyingData.t.size = nonceLen;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Quote,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc == 0) {
	}
	else {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("ERROR: quote: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	    rc = EXIT_FAILURE;
	}
    }
    /* attestation quote to string */
    if (rc == 0) {
	*quoted = out.quoted;
	*signature = out.signature;
    }
    return rc;
}

/* readPcrs() reads all the TPM PCRs.  It reads one PCR at a time.

   It reads the banks specified by pcrSelection, but ignores the bit mask and reads all PCRs.
*/

uint32_t readPcrs(TSS_CONTEXT *tssContext,
		  TPML_PCR_BANKS *pcrBanks,
		  const TPML_PCR_SELECTION *pcrSelection)
{
    TPM_RC			rc = 0;
    PCR_Read_In 		in;
    PCR_Read_Out 		out;
    uint32_t			bank;	/* iterate through PCR banks */

    /* read all banks, one PCR at a time */
    pcrBanks->count  = pcrSelection->count;
    in.pcrSelectionIn.count = pcrSelection->count;

    /* set the count and hash algorithm, same for all PCRs */
    for (bank = 0 ; bank < pcrSelection->count ; bank++) {
	pcrBanks->pcrBank[bank].count = IMPLEMENTATION_PCR;
	pcrBanks->pcrBank[bank].hash = pcrSelection->pcrSelections[bank].hash;
	in.pcrSelectionIn.pcrSelections[bank].hash = pcrSelection->pcrSelections[bank].hash;
	in.pcrSelectionIn.pcrSelections[bank].sizeofSelect =
	    pcrSelection->pcrSelections[bank].sizeofSelect;	/* should be 3 */
    }

    uint8_t 	selectByte;	/* all bytes of PCR select */
    uint8_t 	selectBit;	/* bit map within a byte */
    uint32_t	pcrNum;		/* iterate through PCRs */

    /* iterate through each select byte */
    for (selectByte = 0, pcrNum = 0 ; selectByte < (IMPLEMENTATION_PCR/8) ; selectByte++) {
	/* iterate through each bit in the byte */
	for (selectBit = 0 ; selectBit < 8 ; selectBit++, pcrNum++) {

	    for (bank = 0 ; (rc == 0) && (bank < pcrSelection->count) ; bank++) {
		in.pcrSelectionIn.pcrSelections[bank].pcrSelect[0] = 0;
		in.pcrSelectionIn.pcrSelections[bank].pcrSelect[1] = 0;
		in.pcrSelectionIn.pcrSelections[bank].pcrSelect[2] = 0;
		in.pcrSelectionIn.pcrSelections[bank].pcrSelect[selectByte] = 1 << selectBit;
	    }
	    /* call TSS to execute the command */
	    if (rc == 0) {
		rc = TSS_Execute(tssContext,
				 (RESPONSE_PARAMETERS *)&out,
				 (COMMAND_PARAMETERS *)&in,
				 NULL,
				 TPM_CC_PCR_Read,
				 TPM_RH_NULL, NULL, 0);
	    }
	    if (rc == 0) {
		/* iterate through the banks and copy the PCR value to
		   pcrBanks->pcrBank[bank].digests[pcrNum].t. */
		for (bank = 0 ; (rc == 0) && (bank < pcrSelection->count) ; bank++) {
		    if (pcrSelection->pcrSelections[bank].hash == TPM_ALG_SHA256) {
			pcrBanks->pcrBank[bank].digests[pcrNum].t.size = SHA256_DIGEST_SIZE;
			memcpy(pcrBanks->pcrBank[bank].digests[pcrNum].t.buffer,
			       out.pcrValues.digests[bank].t.buffer,
			       SHA256_DIGEST_SIZE);
		    }
		    else if (pcrSelection->pcrSelections[bank].hash == TPM_ALG_SHA1) {
			pcrBanks->pcrBank[bank].digests[pcrNum].t.size = SHA1_DIGEST_SIZE;
			memcpy(pcrBanks->pcrBank[bank].digests[pcrNum].t.buffer,
			       out.pcrValues.digests[bank].t.buffer,
			       SHA1_DIGEST_SIZE);
		    }
		    else {
			printf("ERROR: readPcrs: does not support algorithm %04x yet\n",
			       pcrSelection->pcrSelections[bank].hash);
			rc = EXIT_FAILURE;
		    }
		}
	    }
	    else {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("ERROR: readPcrs: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	    }
	}
    }
    return rc;
}

TPM_RC flushContext(TSS_CONTEXT *tssContext,
		    TPM_HANDLE handle)
{
    TPM_RC			rc = 0;
    FlushContext_In 		in;

    if (vverbose) printf("flushContext: Entry, handle %08x\n", handle);
    if (rc == 0) {
	in.flushHandle = handle;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	if (vverbose) printf("INFO: flushContext: TPM2_FlushContext success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ERROR: flushcontext: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

