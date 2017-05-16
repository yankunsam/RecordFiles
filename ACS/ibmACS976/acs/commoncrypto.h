/********************************************************************************/
/*										*/
/*		 	TPM 2.0 Attestation - Common Crypto	  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commoncrypto.h 912 2017-01-16 19:40:40Z kgoldman $		*/
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

#ifndef COMMONCRYPTO_H
#define COMMONCRYPTO_H

#include <stdio.h>
#include <stdint.h>

#define TPM_AES_BLOCK_SIZE 16

/* Certificate duration period is hard coded to 20 years */

#define CERT_DURATION (60 * 60 * 24 * ((365 * 20) + 2))		/* +2 for leap years */

/* certificate key to nid mapping array */

typedef struct tdCertificateName
{
    const char *key;
    int nid;
} CertificateName;

TPM_RC createCertificate(char **x509CertString,
			 char **pemCertString,
			 uint32_t *certLength,
			 unsigned char **certificate,
			 TPMT_PUBLIC *tpmtPublic,	
			 const char *caKeyFileName,
			 size_t issuerEntriesSize,
			 char **issuerEntries,
			 size_t subjectEntriesSize,
			 char **subjectEntries,
			 const char *caKeyPassword);
TPM_RC startCertificate(X509 *x509Certificate,
			uint16_t keyLength,
			const unsigned char *keyBuffer,
			size_t issuerEntriesSize,
			char **issuerEntries,
			size_t subjectEntriesSize,
			char **subjectEntries);
TPM_RC addCertKeyRsa(X509 *x509Certificate,
		     uint32_t keyLength,
		     const unsigned char *keyBuffer);
TPM_RC addCertKeyEcc(X509 *x509Certificate,
		     const TPMS_ECC_POINT *tpmsEccPoint);
TPM_RC addCertSignatureRoot(X509 *x509Certificate,
			    const char *caKeyFileName,
			    const char *caKeyPassword);
TPM_RC convertX509ToDer(uint32_t *certLength,
			unsigned char **certificate,
			X509 *x509Certificate);
TPM_RC convertX509ToPem(char **pemString,
			X509 *x509);
TPM_RC convertX509DerToPem(char **pemString,
			   unsigned char *derBin,
			   uint32_t derBinLen);
uint32_t convertX509ToString(char **x509String,
			     X509 *x509);
uint32_t convertPemToX509(X509 **x509,
			  const char *pemCertificate);
uint32_t convertX509ToRsa(RSA  **rsaPkey,
			  X509 *x509);
uint32_t convertX509ToEc(EC_KEY **ecKey,
			 X509 *x509);
uint32_t convertBin2Bn(BIGNUM **bn, const unsigned char *bin, unsigned int bytes);


TPM_RC calculateNid(void);
TPM_RC createX509Name(X509_NAME **x509Name,
		      size_t entriesSize,
		      char **entries);

uint32_t aesencrypt(uint8_t **encData,
		    uint32_t *encDataLen,
		    uint8_t *decData,
		    uint32_t decDataLen,
		    TPM2B_DIGEST *encryptionKey);
uint32_t aesdecrypt(unsigned char **decData,
		    uint32_t *decDataLen,
		    const unsigned char *encData,
		    uint32_t encDataLen,
		    TPM2B_DIGEST *decryptionKey);

#endif
