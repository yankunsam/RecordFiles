/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Server JSON Handler   			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: serverjson.c 871 2016-12-15 21:34:19Z kgoldman $		*/
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

#include <netinet/in.h>

#include <json/json.h>

#include "commonerror.h"
#include "commonutils.h"
#include "commonjson.h"
#include "serverjson.h"

extern int verbose;
extern int vverbose;

/* JS_Command_GetCommand() parses cmdBuffer to a json object cmdJson.  It then extracts the command
   string from the command json.

*/

/* FIXME should do some sanity checking of the command length */

uint32_t JS_Cmd_GetCommand(const char **commandString,
			   json_object **cmdJson,
			   const char *cmdBuffer,
			   uint32_t cmdLength)
{
    uint32_t  rc = 0;
    
    cmdLength = cmdLength;

    /* parse json stream to object */
    if (rc == 0) {
	*cmdJson = json_tokener_parse((char *)cmdBuffer);
	if (cmdJson == NULL) {
	    printf("ERROR: JS_Cmd_GetCommand: could not parse command\n");
	    rc = ACE_JSON_COMMAND;
	}
    }
    if (rc == 0) {
	rc = JS_ObjectGetString(commandString, "command", *cmdJson);
    }
    if (rc == 0) {
	if (vverbose) printf("JS_Command_GetCommand: %s\n", *commandString);
    }
    return rc;
}

/* JS_Cmd_GetPCR() gets a PCR string based on the PCR number pcrNum

   Gets both the SHA-1 and SHA-256 strings.
*/

uint32_t JS_Cmd_GetPCR(const char **pcrSha1String,
		       const char **pcrSha256String,
		       unsigned int pcrNum,
		       json_object *cmdJson)
{
    uint32_t  rc = 0;
    char objName[12];
    if (rc == 0) {
	sprintf(objName, "pcr%usha1", pcrNum);
	rc = JS_ObjectGetString(pcrSha1String,
				objName,
				cmdJson);
    }
    if (rc == 0) {
	sprintf(objName, "pcr%usha256", pcrNum);
	rc = JS_ObjectGetString(pcrSha256String,
				objName,
				cmdJson);
    }
    return rc;
}

/* JS_Cmd_GetEvent() gets an event based on the event number eventNum */

uint32_t JS_Cmd_GetEvent(const char **eventString,
			 unsigned int eventNum,
			 json_object *cmdJson)
{
    uint32_t  rc = 0;
    /* json_object *eventJson = NULL; */
    char objName[12];			/* FIXME */
    sprintf(objName, "event%u", eventNum);
    if (rc == 0) {
	rc = JS_ObjectGetString(eventString,
				objName,
				cmdJson);
    }
    return rc;
}

/* JS_Cmd_GetImaEntry() gets an the imaentry value as an unsigned int */

uint32_t JS_Cmd_GetImaEntry(unsigned int *imaEntry,
			    json_object *cmdJson)
{
    uint32_t  rc = 0;
    const char *imaEntryString = NULL;
    
    if (rc == 0) {
	rc = JS_ObjectGetString(&imaEntryString, "imaentry", cmdJson);
    }
    if (rc == 0) {
	sscanf(imaEntryString, "%u", imaEntry);
    }
    return rc;
}

/* JS_StringToArray() converts a hexascii string to a byte array

   The string length must be exactly twice the array length.
*/

uint32_t JS_StringToArray(uint8_t *array,
			  size_t arrayLength,
			  const char *string)
{
    int rc = 0;

    if (rc == 0) {
	if (strlen(string) != (arrayLength * 2)) {
	    printf("ERROR: JS_StringToArray: string length %u is not %u\n",
		   (unsigned int)strlen(string), (unsigned int)arrayLength);
	    rc = ACE_HEXASCII;
	}
    }
    /* convert the string to binary */
    unsigned int i;
    char ascii[3];
    unsigned int hex;
    ascii[2] = '\0';
    for (i = 0 ; (rc == 0) && (i < arrayLength) ; i++) {
	memcpy(ascii, string +(i*2), 2);
	int irc = sscanf(ascii, "%x", &hex);
	*(array+i) = hex & 0xff;
	if (irc != 1) {
	    printf("ERROR: JS_StringToArray: invalid hexascii\n");
	    rc = ACE_HEXASCII;
	}
	/* printf("JS_StringToArray: array %u is %02x\n", i, *(array+i)); */
    }
    return rc;
}

/* JS_Rsp_AddError() constructs an error json response of the form

   {
   "error":"nnnnnnnn"
   }

*/

uint32_t JS_Rsp_AddError(json_object *responseJson,
			 uint32_t errorCode)
{
    uint32_t  	rc = 0;
    uint32_t 	errorCodeNbo = htonl(errorCode);
    char 	*errorCodeString = NULL;

    if (rc == 0) {
	rc = Array_PrintMalloc(&errorCodeString,		/* freed by caller */
			       (const uint8_t *)&errorCodeNbo,
			       sizeof(uint32_t));
    }
    if (rc == 0) {
	json_object_object_add(responseJson, "error",
			       json_object_new_string(errorCodeString));
    }
    free(errorCodeString);
    return rc;
   
}

