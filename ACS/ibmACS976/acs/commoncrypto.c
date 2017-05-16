/********************************************************************************/
/*										*/
/*			TPM 2.0 Attestation - Common Crypto	  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commoncrypto.c 912 2017-01-16 19:40:40Z kgoldman $		*/
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

#include "openssl/pem.h"
#include <openssl/aes.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssfile.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tsscrypto.h>
#include "ekutils.h"

#include "commonerror.h"

#include "commoncrypto.h"

extern int verbose;
extern int vverbose;

/* createCertificate() constructs a certificate from the issuer and subject.  The public key to be
   certified is tpmtPublic.

   It signs the certificate using the CA key in caKeyFileName protected by the password
   caKeyPassword.  The CA signing key algorithm caKeyAlg is RSA or ECC.

   The certificate is returned as a DER encoded array 'certificate', a PEM string, and a formatted
   string.

*/

TPM_RC createCertificate(char **x509CertString,		/* freed by caller */
			 char **pemCertString,		/* freed by caller */
			 uint32_t *certLength,		/* output, certificate length */
			 unsigned char **certificate,	/* output, freed by caller */
			 TPMT_PUBLIC *tpmtPublic,	/* key to be certified */	
			 const char *caKeyFileName,
			 size_t issuerEntriesSize,
			 char **issuerEntries,
			 size_t subjectEntriesSize,
			 char **subjectEntries,
			 const char *caKeyPassword)
{
    TPM_RC 		rc = 0;
    X509 		*x509Certificate = NULL;
    uint16_t 		publicKeyLength;
    const unsigned char *publicKey;
    
    /* allocate memory for the X509 structure */
    if (rc == 0) {
	x509Certificate = X509_new();		/* freed @2 */
	if (x509Certificate == NULL) {
	    printf("ERROR: createCertificate: Error in X509_new\n");
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    /* hash unique field to create serial number */
    if (rc == 0) {
	if (tpmtPublic->type == TPM_ALG_RSA) {
	    publicKeyLength = tpmtPublic->unique.rsa.t.size;
	    publicKey = tpmtPublic->unique.rsa.t.buffer;
	}
	else if (tpmtPublic->type == TPM_ALG_ECC) {
	    publicKeyLength = tpmtPublic->unique.ecc.x.t.size;
	    publicKey = tpmtPublic->unique.ecc.x.t.buffer;
	}
	else {
	    printf("ERROR: createCertificate: public key algorithm %04x not supported\n",
		   tpmtPublic->type);
	    rc = ACE_BAD_ALGORITHM;
	}
    }    
    /* fill in basic X509 information */
    if (rc == 0) {
	rc = startCertificate(x509Certificate,
			      publicKeyLength, publicKey,
			      issuerEntriesSize, issuerEntries,
			      subjectEntriesSize, subjectEntries);
    }
    /* add the TPM public key to be certified */
     if (rc == 0) {
	 if (tpmtPublic->type == TPM_ALG_RSA) {
	     rc = addCertKeyRsa(x509Certificate, publicKeyLength, publicKey);
	 }
	 else if (tpmtPublic->type == TPM_ALG_ECC) {
	     rc = addCertKeyEcc(x509Certificate, &tpmtPublic->unique.ecc);
	 }
	 else {
	     printf("ERROR: createCertificate: public key algorithm %04x not supported\n",
		    tpmtPublic->type);
	     rc = ACE_BAD_ALGORITHM;
	 }
    }
    /* sign the certificate with the root CA key */
    if (rc == 0) {
	rc = addCertSignatureRoot(x509Certificate, caKeyFileName, caKeyPassword);
    }
    if (rc == 0) {
	rc = convertX509ToDer(certLength, certificate,	/* freed by caller */
			      x509Certificate);		/* in */
    }
    if (rc == 0) {
	rc = convertX509ToPem(pemCertString,		/* freed by caller */
			      x509Certificate);
    }
    if (rc == 0) {
	rc = convertX509ToString(x509CertString,	/* freed by caller */
				 x509Certificate);
    }
    X509_free(x509Certificate);		/* @2 */
    return rc;
}

/* startCertificate() fills in basic X509 information, such as:
   version
   serial number
   issuer
   validity
   subject
*/

TPM_RC startCertificate(X509 *x509Certificate,	/* X509 certificate to be generated */
			uint16_t keyLength,
			const unsigned char *keyBuffer,	/* key to be certified */
			size_t issuerEntriesSize,
			char **issuerEntries,		/* certificate issuer */
			size_t subjectEntriesSize,
			char **subjectEntries)		/* certificate subject */
{
    TPM_RC 		rc = 0;			/* general return code */
    int			irc;			/* integer return code */
    ASN1_TIME 		*arc;			/* return code */
    ASN1_INTEGER 	*x509Serial;		/* certificate serial number in ASN1 */
    BIGNUM 		*x509SerialBN;		/* certificate serial number as a BIGNUM */
    unsigned char 	x509Serialbin[SHA1_DIGEST_SIZE]; /* certificate serial number in binary */
    X509_NAME 		*x509IssuerName;	/* composite issuer name, key/value pairs */
    X509_NAME 		*x509SubjectName;	/* composite subject name, key/value pairs */

    x509IssuerName = NULL;	/* freed @1 */
    x509SubjectName = NULL;	/* freed @2 */
    x509SerialBN = NULL;	/* freed @3 */ 

    /* add certificate version X509 v3 */
    if (rc == 0) {
	irc = X509_set_version(x509Certificate, 2L);	/* value 2 == v3 */
	if (irc != 1) {
	    printf("ERROR: startCertificate: Error in X509_set_version\n");
	    rc = ASE_OSSL_X509;
	}
    }
    /*
      add certificate serial number
    */
    if (rc == 0) {
	if (vverbose) printf("startCertificate: Adding certificate serial number\n");
	/* to create a unique serial number, hash the key to be certified */
	SHA1(keyBuffer, keyLength, x509Serialbin);
	/* convert the SHA1 digest to a BIGNUM */
	x509SerialBN = BN_bin2bn(x509Serialbin, SHA1_DIGEST_SIZE, x509SerialBN);
	if (x509SerialBN == NULL) {
	    printf("ERROR: startCertificate: Error in serial number BN_bin2bn\n");
	    rc = ASE_OSSL_BN;
	}
    }
    if (rc == 0) {
	/* get the serial number structure member, can't fail */
	x509Serial = X509_get_serialNumber(x509Certificate);
	/* convert the BIGNUM to ASN1 and add to X509 certificate */
	x509Serial = BN_to_ASN1_INTEGER(x509SerialBN, x509Serial);
	if (x509Serial == NULL) {
	    printf("ERROR: startCertificate: Error setting certificate serial number\n");
	    rc = ASE_OSSL_BN;
	}
    }
    /* add issuer */
    if (rc == 0) {
	if (vverbose) printf("startCertificate: Adding certificate issuer\n");
	rc = createX509Name(&x509IssuerName,
			    issuerEntriesSize,
			    issuerEntries);
    }
    if (rc == 0) {
	irc = X509_set_issuer_name(x509Certificate, x509IssuerName);
	if (irc != 1) {
	    printf("ERROR: startCertificate: Error setting certificate issuer\n");
	    rc = ASE_OSSL_X509;
	}
    }
    /* add validity */
    if (rc == 0) {
	if (vverbose) printf("startCertificate: Adding certificate validity\n");
	/* can't fail, just returns a structure member */
	ASN1_TIME *notBefore = X509_get_notBefore(x509Certificate);
	arc = X509_gmtime_adj(notBefore ,0L);			/* set to today */
	if (arc == NULL) {
	    printf("ERROR: startCertificate: Error setting notBefore time\n");
	    rc = ASE_OSSL_X509;
	}
    }
    if (rc == 0) {
	/* can't fail, just returns a structure member */
	ASN1_TIME *notAfter = X509_get_notAfter(x509Certificate);
	X509_gmtime_adj(notAfter, CERT_DURATION);	/* set to duration */
	if (arc == NULL) {
	    printf("ERROR: startCertificate: Error setting notAfter time\n");
	    rc = ASE_OSSL_X509;
	}
    }
    /* add subject */
    if (rc == 0) {
	if (vverbose) printf("startCertificate: Adding certificate subject\n");
	rc = createX509Name(&x509SubjectName,
			    subjectEntriesSize,
			    subjectEntries);
    }
    if (rc == 0) {
	irc = X509_set_subject_name(x509Certificate, x509SubjectName);
	if (irc != 1) {
	    printf("ERROR: startCertificate: Error setting certificate subject\n");
	    rc = ASE_OSSL_X509;
	}
    }
    /* cleanup */
    X509_NAME_free(x509IssuerName);		/* @1 */
    X509_NAME_free(x509SubjectName);		/* @2 */
    BN_free(x509SerialBN);			/* @3 */
    return rc;
}

/* These are the names inserted into the certificates.  If changed, the entries also change.  At run
   time, the mapping from key to nid is done once and used repeatedly.  */
    
CertificateName certificateName[] = {
    { "countryName",			NID_undef},	/* 0 */
    { "stateOrProvinceName",		NID_undef},	/* 1 */
    { "localityName",			NID_undef},	/* 2 */
    { "organizationName",		NID_undef},	/* 3 */
    { "organizationalUnitName",		NID_undef},	/* 4 */
    { "commonName",			NID_undef},	/* 5 */
    { "emailAddress",			NID_undef},	/* 6 */
};

TPM_RC calculateNid(void)
{
    TPM_RC rc = 0;
    size_t 	i;

    /* if (vverbose) printf("calculateNid:\n"); */
    for (i=0 ; (i < sizeof(certificateName)/sizeof(CertificateName)) && (rc == 0) ; i++) {
	certificateName[i].nid = OBJ_txt2nid(certificateName[i].key);	/* look up the NID for the
									   field */
	if (certificateName[i].nid == NID_undef) {
	    printf("ERROR: calculateNid: Error finding nid for %s\n", certificateName[i].key);
	    rc = ASE_OSSL_NID;
	}
    }
    return rc;
}

/* createX509Name() create an X509 name (issuer or subject) from a pointer to issuer or subject
   entries

*/

TPM_RC createX509Name(X509_NAME **x509Name,
		      size_t entriesSize,
		      char **entries)
{
    TPM_RC 	rc = 0;		/* general return code */
    int		irc;		/* integer return code */
    size_t  	i;
    X509_NAME_ENTRY 	*nameEntry;			/* single field of the name */

    nameEntry = NULL;

    if (rc == 0) {
	*x509Name = X509_NAME_new();
	if (*x509Name == NULL) {
	    printf("ERROR: createX509Name: Error in X509_NAME_new()\n");
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    for (i=0 ; (i < entriesSize) && (rc == 0) ; i++) {
	if ((rc == 0) && (entries[i] != NULL)) {
	    nameEntry =
		X509_NAME_ENTRY_create_by_NID(NULL,		/* caller creates object */
					      certificateName[i].nid,
					      MBSTRING_ASC,	/* character encoding */
					      (unsigned char *)entries[i],	/* to add */
					      -1);		/* length, -1 is C string */

	    if (nameEntry == NULL) {
		printf("ERROR: createX509Name: Error creating entry for %s\n",
		       certificateName[i].key);
		rc = ASE_OSSL_X509;
	    }
	}
	if ((rc == 0) && (entries[i] != NULL)) {
	    irc = X509_NAME_add_entry(*x509Name,	/* add to issuer */
				      nameEntry,	/* add the entry */
				      -1,		/* location - append */	
				      0);		/* set - not multivalued */
	    if (irc != 1) {
		printf("ERROR: createX509Name: Error adding entry for %s\n",
		       certificateName[i].key);
		rc = ASE_OSSL_X509;
	    }
	}
	X509_NAME_ENTRY_free(nameEntry);	/* callee checks for NULL */
	nameEntry = NULL;
    }
    return rc;
}

/* addCertKeyRsa() adds the TPM RSA public key (the key to be certified) to the openssl X509
   certificate

 */

TPM_RC addCertKeyRsa(X509 *x509Certificate,
		     uint32_t keyLength,
		     const unsigned char *keyBuffer)	/* key to be certified */
{
    TPM_RC 		rc = 0;		/* general return code */
    int			irc;		/* integer return code */

    /* public key to be certified */
    RSA 	  	*rsaPubKey;		/* OpenSSL key token */
    EVP_PKEY 		*evpPubkey;		/* EVP format */

    evpPubkey = NULL;		/* freed @1 */
    rsaPubKey = NULL;		/* freed @2 */
    
    if (vverbose) printf("addCertKeyRsa: add public key to certificate\n");
    /* convert from TPM keydata format to openSSL RSA type */
    if (rc == 0) {
	/* public exponent */
	unsigned char earr[3] = {0x01, 0x00, 0x01};
	rc = TSS_RSAGeneratePublicToken(&rsaPubKey,		/* freed by caller */
					keyBuffer,      	/* public modulus */
					keyLength,
					earr,      		/* public exponent */
					sizeof(earr));
    }
    if (rc == 0) {
	evpPubkey = EVP_PKEY_new();
	if (evpPubkey == NULL) {
	    printf("ERROR: addCertKeyRsa: Error allocating EVP format key\n");
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    /* convert from OpenSSL RSA to EVP_PKEY type */
    if (rc == 0) {
	irc = EVP_PKEY_assign_RSA(evpPubkey, rsaPubKey);
	if (irc != 1) {
	    printf("ERROR: addCertKeyRsa: Error converting public key from RSA to EVP format\n");
	    rc = ASE_OSSL_RSA;
	}
    }
    /* add the public key to the certificate */
    if (rc == 0) {
	irc = X509_set_pubkey(x509Certificate, evpPubkey);
	if (irc != 1) {
	    printf("ERROR: addCertKeyRsa: Error adding public key to certificate\n");
	    rc = ASE_OSSL_X509;
	}
    }
    /* cleanup */
    if (evpPubkey != NULL) {
	EVP_PKEY_free(evpPubkey);	/* @1 */
	rsaPubKey = NULL;	/* I think freeing the EVP object implicitly frees the RSA object */
    }
    if (rsaPubKey != NULL) {
	RSA_free(rsaPubKey);		/* @2 */	
    }
    return rc;
}

/* addCertKeyEcc() adds the TPM ECC public key (the key to be certified) to the openssl X509
   certificate

 */

TPM_RC addCertKeyEcc(X509 *x509Certificate,
		     const TPMS_ECC_POINT *tpmsEccPoint)
{
    TPM_RC 		rc = 0;			/* general return code */
    int			irc;
    EVP_PKEY 		*evpPubkey;	/* EVP format */
    EC_KEY 		*ecKey;			/* EC_KEY token format */
    EC_GROUP 		*ecGroup;
    BIGNUM 		*x;
    BIGNUM 		*y;
    
    /* public key to be certified */
    evpPubkey = NULL;		/* freed @1 */
    ecKey = NULL;		/* freed @2 */
    x = NULL;			/* freed @3 */
    y = NULL;			/* freed @4 */
    
    /* convert from TPM key to openssl EC_KEY type */
    if (rc == 0) {
	ecKey = EC_KEY_new();
	if (ecKey == NULL) {
	    printf("ERROR: addCertKeyEcc: Error creating EC_KEY\n");
	    rc = ACE_OSSL_ECC;
	}
    }
    if (rc == 0) {
	ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (ecGroup == NULL) {
	    printf("ERROR: addCertKeyEcc: Error in EC_GROUP_new_by_curve_name\n");
	    rc = ACE_OSSL_ECC;
	}
    }
    if (rc == 0) {
	EC_GROUP_set_asn1_flag(ecGroup, OPENSSL_EC_NAMED_CURVE);	/* returns void */
    }
    /* assign curve to EC_KEY */
    if (rc == 0) {
	irc = EC_KEY_set_group(ecKey, ecGroup);
	if (irc != 1) {
	    printf("ERROR: addCertKeyEcc: Error in EC_KEY_set_group\n");
	    rc = ACE_OSSL_ECC;
	}
    }
    if (rc == 0) {
        rc = convertBin2Bn(&x,				/* freed by caller */
			   tpmsEccPoint->x.t.buffer,
			   tpmsEccPoint->x.t.size);	
    }
    if (rc == 0) {
        rc = convertBin2Bn(&y,				/* freed by caller */
			   tpmsEccPoint->y.t.buffer,
			   tpmsEccPoint->y.t.size);
    }
    if (rc == 0) {
	irc = EC_KEY_set_public_key_affine_coordinates(ecKey, x, y);
	if (irc != 1) {
	    printf("ERROR: addCertKeyEcc: Error converting public key from X Y to EC_KEY format\n");
	    rc = ACE_OSSL_ECC;
	}
    }
    /* convert OpenSSL key token EC_KEY to EVP_PKEY */
    if (rc == 0) {
	evpPubkey = EVP_PKEY_new();
	if (evpPubkey == NULL) {
	    printf("ERROR: addCertKeyEcc: Error allocating EVP format key\n");
	    rc = ACE_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_set1_EC_KEY(evpPubkey, ecKey);
	if (irc != 1) {
	    printf("ERROR: addCertKeyEcc: Error converting public key from EC to EVP format\n");
	    rc = ACE_OSSL_ECC;
	}
    }
    /* add the public key to the certificate */
    if (rc == 0) {
	irc = X509_set_pubkey(x509Certificate, evpPubkey);
	if (irc != 1) {
	    printf("ERROR: addCertKeyEcc: Error adding public key to certificate\n");
	    rc = ACE_OSSL_X509;
	}
    }
    /* cleanup */
    if (evpPubkey != NULL) {
	EVP_PKEY_free(evpPubkey);	/* @1 */
    }
    if (ecKey != NULL) {
	EC_KEY_free(ecKey);		/* @2 */
    }
    return rc;
}

/* addCertSignatureRoot() uses the openSSL root key to sign the X509 certificate.

   As a sanity check, it verifies the certificate.
*/

TPM_RC addCertSignatureRoot(X509 *x509Certificate,	/* certificate to be signed */
			    const char *caKeyFileName,	/* openSSL root CA key password */
			    const char *caKeyPassword)
{
    TPM_RC 		rc = 0;		/* general return code */
    int			irc;		/* integer return code */

    /* signing key */
    RSA 	  	*rsaSignKey;		/* OpenSSL key token */
    const EVP_MD	*digest;		/* signature digest algorithm */
    EVP_PKEY 		*evpSignkey;		/* EVP format */

    evpSignkey = NULL;		/* freed @1 */
    rsaSignKey = NULL;		/* freed @2 */

    if (vverbose) printf("addCertSignatureRoot:\n");

    /* open the CA signing key file */
    FILE 	*fp = NULL;
    if (rc == 0) {
	fp = fopen(caKeyFileName,"r");
	if (fp == NULL) {
	    printf("ERROR: addCertSignatureRoot: Error, Cannot open %s\n", caKeyFileName);
	    rc = ASE_FILE_READ;
	}
    }
    /* convert the CA signing key from PEM to EVP_PKEY format */
    if (rc == 0) {
	evpSignkey = PEM_read_PrivateKey(fp, NULL, NULL, (void *)caKeyPassword);	
	if (evpSignkey == NULL) {
	    printf("ERROR: addCertSignatureRoot: Error calling PEM_read_PrivateKey() from %s\n",
		   caKeyFileName);
	    rc = ASE_OSSL_PEM;
	}
    }
    /* close the CA signing key file */
    if (fp != NULL) { 
	fclose(fp);
    }
    /* set the certificate signature digest algorithm */
    if (rc == 0) {
	digest = EVP_sha256();	/* no error return */
    }
    /* sign the certificate with the root CA signing key */
    if (rc == 0) {
	if (vverbose) printf("addCertSignatureRoot: Signing the certificate\n");
	irc = X509_sign(x509Certificate, evpSignkey, digest);
	if (irc == 0) {	/* returns signature size, 0 on error */
	    printf("ERROR: addCertSignature: Error signing certificate\n");
	    rc = ASE_OSSL_X509;
	}
    }
    /* verify the signature */
    if (rc == 0) {
	if (vverbose) printf("addCertSignatureRoot: Verifying the certificate\n");
	irc = X509_verify(x509Certificate, evpSignkey);
	if (irc != 1) {
	    printf("ERROR: addCertSignatureRoot: Error verifying certificate\n");
	    rc = ASE_OSSL_X509;
	}
    }
    /* cleanup */
    if (evpSignkey != NULL) {
	EVP_PKEY_free(evpSignkey);	/* @1 */
	rsaSignKey = NULL;	/* I think freeing the EVP object implicitly frees the RSA object */
    }
    if (rsaSignKey != NULL) {
	RSA_free(rsaSignKey);		/* @2 */	
    }
    return rc;
}

/* convertX509ToDer() serializes the openSSL X509 structure to a DER certificate

 */

TPM_RC convertX509ToDer(uint32_t *certLength,
			unsigned char **certificate,	/* output, freed by caller */
			X509 *x509Certificate)		/* input */
{
    TPM_RC 		rc = 0;		/* general return code */
    int			irc;

    /* for debug */
    if ((rc == 0) && vverbose) {
	irc = X509_print_fp(stdout, x509Certificate);
	if (irc != 1) {
	    printf("ERROR: convertX509ToDer: Error in certificate print X509_print_fp()\n");
	    rc = ASE_OSSL_X509;
	}
    }
    /* sanity check for memory leak */
    if (rc == 0) {
	if (*certificate != NULL) {
	    printf("ERROR: convertX509ToDer: Error, certificate not NULL at entry\n");
	    rc = ASE_OUT_OF_MEMORY;
	}	
    }
    /* convert the X509 structure to binary (internal to DER format) */
    if (rc == 0) {
	if (vverbose) printf("convertX509ToDer: Serializing certificate\n");
	irc = i2d_X509(x509Certificate, certificate);
	if (irc < 0) {
	    printf("ERROR: convertX509ToDer: Error in certificate serialization i2d_X509()\n");
	    rc = ASE_OSSL_X509;
	}
	else {
	    *certLength = irc; 
	}
    }
    return rc;
}

/* convertX509ToPem() converts an OpenSSL X509 structure to PEM format */

TPM_RC convertX509ToPem(char **pemString,	/* freed by caller */
			X509 *x509)
{
    TPM_RC 		rc = 0;		/* general return code */
    int			irc;
    
    /* create a BIO that uses an in-memory buffer */
    BIO *bio = NULL;
    if (rc == 0) {
	bio = BIO_new(BIO_s_mem());		/* freed @1 */
	if (bio == NULL) {
	    printf("ERROR: convertX509ToPem: BIO_new failed\n");  
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    /* convert X509 to PEM and write the PEM to memory */
    if (rc == 0) {
	irc = PEM_write_bio_X509(bio, x509);
	if (irc != 1) {
	    printf("ERROR: convertX509ToPem PEM_write_bio_X509 failed\n");
	    rc = ASE_OSSL_PEM;
	}
    }
    char *data = NULL;
    long length;
    if (rc == 0) {
	length = BIO_get_mem_data(bio, &data);
	*pemString = malloc(length+1);
	if (*pemString == NULL) {
	    printf("ERROR: convertX509ToPem: Cannot malloc %lu\n", length);  
	    rc = ASE_OUT_OF_MEMORY;
	}
	else {
	    (*pemString)[length] = '\0';
	}
    }
    if (rc == 0) {
	irc = BIO_read(bio, *pemString, length);
 	if (irc <= 0) {
	    printf("ERROR: convertX509ToPem BIO_read failed\n");
	    rc = ASE_OSSL_BIO;
	}
    }
    if (bio != NULL) {
	BIO_free(bio);			/* @1 */
    }
    return rc;
}

/* convertX509DerToPem() converts an OpenSSL DER stream to PEM format */

TPM_RC convertX509DerToPem(char **pemString,	/* freed by caller */
			   unsigned char *derBin,
			   uint32_t derBinLen)
{
    uint32_t 		rc = 0;
    X509 		*x509 = NULL;;
    unsigned char 	*tmpPtr;	/* because d2i_X509 moves the ptr */
    
    /* convert DER to X509 */
    if (rc == 0) {
	tmpPtr = derBin;
	x509 = d2i_X509(NULL, (const unsigned char **)&tmpPtr, derBinLen);
	if (x509 == NULL) {
	    printf("ERROR: convertX509DerToPem failed\n");
	    rc = ASE_OSSL_X509;
	}
    }
    /* convert X509 to PEM */
    if (rc == 0) {
	rc = convertX509ToPem(pemString,	/* freed by caller */
			      x509);
    }
    if (x509 != NULL) {
	X509_free(x509);
    }
    return rc;
}

/* convertX509ToString() converts an OpenSSL X509 structure to a human readable string */

uint32_t convertX509ToString(char **x509String,	/* freed by caller */
			     X509 *x509)
{
    uint32_t 		rc = 0;
    int			irc;

    /* create a BIO that uses an in-memory buffer */
    BIO *bio = NULL;
    if (rc == 0) {
	bio = BIO_new(BIO_s_mem());		/* freed @1 */
	if (bio == NULL) {
	    printf("ERROR: convertX509ToString: BIO_new failed\n");  
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    /* write the string to memory */
    if (rc == 0) {
	irc = X509_print(bio, x509);
	if (irc != 1) {
	    printf("ERROR: convertX509ToString X509_print failed\n");
	    rc = ASE_OSSL_X509;
	}
    }
    char *data = NULL;
    long length;
    if (rc == 0) {
	length = BIO_get_mem_data(bio, &data);
	*x509String = malloc(length+1);
	if (*x509String == NULL) {
	    printf("ERROR: convertX509ToString: Cannot malloc %lu\n", length);  
	    rc = ASE_OUT_OF_MEMORY;
	}
	else {
	    (*x509String)[length] = '\0';
	}
    }
    if (rc == 0) {
	irc = BIO_read(bio, *x509String, length);
 	if (irc <= 0) {
	    printf("ERROR: convertX509ToString BIO_read failed\n");
	    rc = ASE_OSSL_BIO;
	}
    }
    if (bio != NULL) {
	BIO_free(bio);			/* @1 */
    }

    return rc;
    
}

/* convertPemToX509() converts an in-memory PEM format X509 certificate to an openssl X509
   structure.

   It also extracts the public key to an openssl RSA structure.
*/

uint32_t convertPemToX509(X509 **x509,		/* freed by caller */
			  const char *pemCertificate)
{
    uint32_t rc = 0;

    if (vverbose) printf("convertPemToX509: pemCertificate\n%s\n", pemCertificate);  

    BIO *bio = NULL;
    /* create a BIO that uses an in-memory buffer */
    if (rc == 0) {
	bio = BIO_new(BIO_s_mem());		/* freed @1 */
	if (bio == NULL) {
	    printf("ERROR: convertPemToX509: BIO_new failed\n");  
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    /* write the PEM from memory to BIO */
    int pemLength;
    int writeLen = 0;
    if (rc == 0) {
	pemLength = strlen(pemCertificate);
	writeLen = BIO_write(bio, pemCertificate, pemLength);
	if (writeLen != pemLength) {
	    printf("ERROR: convertPemToX509: BIO_write failed\n");  
	    rc = ASE_OSSL_BIO;
	}
    }
    /* convert the properly formatted PEM to X509 structure */
    if (rc == 0) {
	*x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (*x509 == NULL) {
	    printf("\tERROR: convertPemToX509: PEM_read_bio_X509 failed\n");
	    rc = ASE_OSSL_PEM;
	}
    }
    /* for debug */
    if (rc == 0) {
	if (vverbose) X509_print_fp(stdout, *x509);
    }
    if (bio != NULL) {
	BIO_free(bio);			/* @1 */
    }
    return rc;
}

/* convertX509ToRsa extracts the public key from an X509 structure to an openssl RSA structure

 */

uint32_t convertX509ToRsa(RSA  **rsaPkey,	/* freed by caller */
			  X509 *x509)
{
    uint32_t rc = 0;

    if (vverbose) printf("convertX509ToRsa: Entry\n\n");
    
    EVP_PKEY *evpPkey = NULL;

    if (rc == 0) {
	evpPkey = X509_get_pubkey(x509);	/* freed @1 */
	if (evpPkey == NULL) {
	    printf("ERROR: convertX509ToRsa: X509_get_pubkey failed\n");  
	    rc = ASE_OSSL_X509;
	}
    }
    if (rc == 0) {
	*rsaPkey = EVP_PKEY_get1_RSA(evpPkey);
	if (*rsaPkey == NULL) {
	    printf("ERROR: convertX509ToRsa: EVP_PKEY_get1_RSA failed\n");  
	    rc = ASE_OSSL_X509;
	}
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

/* convertX509ToEc extracts the public key from an X509 structure to an openssl RSAEC_KEY structure

 */

uint32_t convertX509ToEc(EC_KEY **ecKey,	/* freed by caller */
			 X509 *x509)
{
    uint32_t rc = 0;

    if (vverbose) printf("convertX509ToEc: Entry\n\n");
    
    EVP_PKEY *evpPkey = NULL;

    if (rc == 0) {
	evpPkey = X509_get_pubkey(x509);	/* freed @1 */
	if (evpPkey == NULL) {
	    printf("ERROR: convertX509ToEc: X509_get_pubkey failed\n");  
	    rc = ASE_OSSL_X509;
	}
    }
    if (rc == 0) {
	*ecKey = EVP_PKEY_get1_EC_KEY(evpPkey);
	if (*ecKey == NULL) {
	    printf("ERROR: convertX509ToEc: EVP_PKEY_get1_EC_KEY failed\n");  
	    rc = ASE_OSSL_X509;
	}
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

/* convertBin2Bn() wraps the openSSL function in an error handler

   Converts a char array to bignum
*/

uint32_t convertBin2Bn(BIGNUM **bn,			/* freed by caller */
		       const unsigned char *bin,
		       unsigned int bytes)
{
    uint32_t rc = 0;

    /* BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
    
       BN_bin2bn() converts the positive integer in big-endian form of length len at s into a BIGNUM
       and places it in ret. If ret is NULL, a new BIGNUM is created.

       BN_bin2bn() returns the BIGNUM, NULL on error.
    */
    if (rc == 0) {
        *bn = BN_bin2bn(bin, bytes, *bn);
        if (*bn == NULL) {
            printf("convertBin2Bn: Error in BN_bin2bn\n");
            rc = ASE_OSSL_BN;
        }
    }
    return rc;
}

/* aesencrypt() uses encryptionKey tp encrypt decData to encData.  PKCS padding is used */

uint32_t aesencrypt(uint8_t **encData,		/* freed by caller */
		    uint32_t *encDataLen,
		    uint8_t *decData,
		    uint32_t decDataLen,
		    TPM2B_DIGEST *encryptionKey)
{
    uint32_t 	rc = 0;
    int		irc = 0;

    /* construct the encryption key */
    AES_KEY aesEncKey;
    if (rc == 0) {
	irc = AES_set_encrypt_key(encryptionKey->t.buffer, 256, &aesEncKey);
	if (irc != 0) {
	    printf("ERROR: aesencrypt: AES_set_encrypt_key failed\n");
            rc = ASE_OSSL_AES;      /* should never occur, null pointers or bad bit size */
        }
    }
    /* allocate memory for the encrypted data */
    uint32_t		padLength;
    if (rc == 0) {
	if (vverbose) printf("aesencrypt: input length %u\n", decDataLen);
        /* calculate the pad length and padded data length */
        padLength = TPM_AES_BLOCK_SIZE - (decDataLen % TPM_AES_BLOCK_SIZE);
        *encDataLen = decDataLen + padLength;
        if (vverbose) printf("aesencrypt: padded length %u pad length %u\n",
			     *encDataLen, padLength);
        /* allocate memory for the encrypted response */
        *encData = malloc(*encDataLen);		/* freed by caller */
	if (*encData == NULL) {
	    printf("ERROR: aesencrypt: could not malloc %u bytes\n",
		   *encDataLen);
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    unsigned char       *decDataPadded = NULL;
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        decDataPadded = malloc(*encDataLen);	/* freed @1 */
	if (decDataPadded == NULL) {
	    printf("ERROR: aesencrypt: could not malloc %u bytes\n",
		   *encDataLen);
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    unsigned char       ivec[TPM_AES_BLOCK_SIZE];       /* initial chaining vector */
    if (rc == 0) {
        /* unpadded original data */
        memcpy(decDataPadded, decData, decDataLen);
	/* pad the decrypted clear text data */
        /* last gets pad = pad length */
        memset(decDataPadded + decDataLen, padLength, padLength);
        /* set the IV */
        memset(ivec, 0, sizeof(ivec));
        /* encrypt the padded input to the output */
        AES_cbc_encrypt(decDataPadded,
                        *encData,
                        *encDataLen,
                        &aesEncKey,
                        ivec,
                        AES_ENCRYPT);
    }
    free(decDataPadded);     /* @1 */
    return rc;
}

/* aesdecrypt() uses encryptionKey tp decrypt encData to decData.  PKCS padding is checked */

uint32_t aesdecrypt(unsigned char **decData,   		/* output decrypted data, caller frees */
		    uint32_t *decDataLen,		/* output */
		    const unsigned char *encData,	/* input encrypted data */
		    uint32_t encDataLen,		/* input */
		    TPM2B_DIGEST *decryptionKey)	/* input AES key */
{
    uint32_t 		rc = 0;
    int			irc = 0;
    uint32_t		i;
    uint32_t		padLength;
    unsigned char       *padData;
    
    if (vverbose) printf("aesdecrypt: Length %u\n", encDataLen);
    /* sanity check encrypted length */
    if (rc == 0) {
	if (encDataLen < TPM_AES_BLOCK_SIZE) {
	    printf("ERROR: aesdecrypt: bad encrypted length %u\n", encDataLen);
	    rc = ACE_OSSL_AES;
	}
    }
    /* construct the decryption key */
    AES_KEY aesEncKey;
    if (rc == 0) {
	irc = AES_set_decrypt_key(decryptionKey->t.buffer, 256, &aesEncKey);
	if (irc != 0) {
	    printf("ERROR: aesencrypt: AES_set_encrypt_key failed\n");
            rc = ASE_OSSL_AES;      /* should never occur, null pointers or bad bit size */
        }
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
	*decData = malloc(encDataLen);		/* freed by caller */
	if (*decData == NULL) {
	    printf("ERROR: aesencrypt: could not malloc %u bytes\n",
		   encDataLen);
	    rc = ASE_OUT_OF_MEMORY;
	}
    }
    /* decrypt the input to the padded output */
    unsigned char       ivec[TPM_AES_BLOCK_SIZE];       /* initial chaining vector */
    if (rc == 0) {
	/* set the IV */
	memset(ivec, 0, sizeof(ivec));
	/* decrypt the padded input to the output */
	AES_cbc_encrypt(encData,
			*decData,
			encDataLen,
			&aesEncKey,
			ivec,
			AES_DECRYPT);
    }
    /* get the pad length */
    if (rc == 0) {
	/* get the pad length from the last byte */
	padLength = (uint32_t)*(*decData + encDataLen - 1);
	/* sanity check the pad length */
	if (vverbose) printf("aesdecrypt: Pad length %u\n", padLength);
	if ((padLength == 0) ||
	    (padLength > TPM_AES_BLOCK_SIZE)) {
	    printf("ERROR: aesdecrypt: illegal pad length %u\n", padLength);
	    rc = ACE_OSSL_AES;
	}
    }
    if (rc == 0) {
	/* get the unpadded length */
	*decDataLen = encDataLen - padLength;
	/* pad starting point */
	padData = *decData + *decDataLen;
	/* sanity check the pad */
	for (i = 0 ; i < padLength ; i++, padData++) {
	    if (*padData != padLength) {
		if (vverbose) printf("aesdecrypt: Error, bad pad %02x at index %u\n",
		       *padData, i);
		rc = ACE_OSSL_AES;
	    }
	}
    }
    return rc;
}


