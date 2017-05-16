/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Common TSS Functions	  		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: commontss.h 898 2017-01-03 20:34:24Z kgoldman $		*/
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

#ifndef COMMONTSS_H
#define COMMONTSS_H

#include <tss2/tss.h>

TPM_RC getTpmVendor(TSS_CONTEXT *tssContext,
		    char 	*tpmVendor);
TPM_RC getCapSrk(TSS_CONTEXT 	*tssContext,
		 int   		*exists);
TPM_RC createSrk(TSS_CONTEXT 	*tssContext,
		 TPM_HANDLE 	*handle);
TPM_RC persistSrk(TSS_CONTEXT 	*tssContext,
		  TPM_HANDLE 	srkHandle);
TPM_RC createAttestationKey(TSS_CONTEXT 	*tssContext,
			    TPMI_RH_NV_INDEX 	nvIndex,
			    TPM2B_PRIVATE 	*attestPriv,
			    TPM2B_PUBLIC 	*attestPub,
			    uint16_t 		*attestPubLength,
			    unsigned char 	**attestPubBin);
TPM_RC loadAttestationKey(TSS_CONTEXT 	*tssContext,
			  TPM_HANDLE 	*handle,
			  TPM2B_PRIVATE *attestPriv,
			  TPM2B_PUBLIC 	*attestPub);
TPM_RC activatecredential(TSS_CONTEXT *tssContext,
			  TPM2B_DIGEST *certInfo,
			  TPM_HANDLE activateHandle,
			  TPM_HANDLE keyHandle,
			  unsigned char *credentialBlobBin,
			  size_t credentialBlobBinSize,
			  unsigned char *secretBin,
			  size_t secretBinSize);
TPM_RC makePolicySession(TSS_CONTEXT *tssContext,
			 TPMI_SH_AUTH_SESSION *sessionHandle);
TPM_RC flushContext(TSS_CONTEXT 	*tssContext,
		    TPM_HANDLE 		handle);
uint32_t readPcrs(TSS_CONTEXT *tssContext,
		  TPML_PCR_BANKS *pcrBanks,
		  const TPML_PCR_SELECTION *pcrSelection);
uint32_t signQuote(TSS_CONTEXT *tssContext,
		   TPM2B_ATTEST *quoted,
		   TPMT_SIGNATURE *signature,
		   TPM_HANDLE keyHandle,
		   TPMI_ALG_PUBLIC type,
		   const unsigned char *nonceBin,
		   size_t nonceLen,
		   const TPML_PCR_SELECTION *pcrSelection);

#endif
