/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client JSON Handler			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: clientjson.h 856 2016-12-12 15:39:27Z kgoldman $		*/
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

#ifndef CLIENTJSON_H
#define CLIENTJSON_H

#include <tss2/tss.h>
#include "eventlib.h"
#include "imalib.h"

uint32_t JS_Cmd_Nonce(uint32_t *length, char **buffer, const char *machineName);
uint32_t JS_Rsp_Nonce(const char **nonce,
		      const char **pcrSelect,
		      json_object *responseObj);

uint32_t JS_Cmd_Quote(uint32_t *length,
		      char **buffer,
		      const char *hostname,
		      const char *boottime,
		      char pcrsha1[][(SHA1_DIGEST_SIZE * 2) + 1],
		      char pcrsha256[][(SHA256_DIGEST_SIZE * 2) + 1],
		      const char *quoted,
		      const char *signature);
uint32_t JS_Rsp_Quote(json_object *responseObj);

uint32_t JS_Cmd_AddImaEntry(json_object *command,
			    const char *imaEntryString);
uint32_t JS_Cmd_NewBiosEntry(json_object **command,
			     const char *hostname,
			     const char *nonc);
uint32_t JS_Cmd_NewImaEntry(json_object **command,
			    const char *hostname,
			    const char *imaEntryString);

uint32_t JS_Cmd_AddEvent(json_object *command,
			 unsigned int lineNum,
			 TCG_PCR_EVENT2 *event2);

uint32_t JS_Cmd_AddImaEvent(json_object *command,
			    ImaEvent 	*imaEvent,
			    unsigned int lineNum);

uint32_t JS_Rsp_Bios(const char **imaentryString,
		     json_object *responseObj);
uint32_t JS_Rsp_Ima(json_object *responseObj);

uint32_t JS_Cmd_EnrollRequest(uint32_t *length,
			      char **buffer,
			      const char *tpmVendor,
			      const char *ekCertificateString,
			      const char *attestPubString,
			      const char *machineName);
uint32_t JS_Cmd_EnrollCert(uint32_t *length,
			   char **buffer,
			   const char *certificateString,
			   const char *machineName);

uint32_t JS_ObjectUnmarshal(json_object **object,
		      const uint8_t *rspBuffer);
void JS_ObjectTrace(const char *message,
		    json_object *object);

#endif
