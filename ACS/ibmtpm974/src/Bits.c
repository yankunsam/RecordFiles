/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Bits.c 809 2016-11-16 18:31:54Z kgoldman $			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2016					*/
/*										*/
/********************************************************************************/

/* 9.2 Bits.c */
/* 9.2.1 Introduction */
/* This file contains bit manipulation routines.  They operate on bit arrays. */
/* The 0th bit in the array is the right-most bit in the 0th octet in the array. */
/* NOTE: If pAssert() is defined, the functions will assert if the indicated bit number is outside
   of the range of bArray. How the assert is handled is implementation dependent. */
/* 9.2.2 Includes */
#include "Tpm.h"
/*     9.2.3 Functions */
/* 9.2.3.1 TestBit() */
/* This function is used to check the setting of a bit in an array of bits. */
/* Return Values Meaning */
/* TRUE bit is set */
/* FALSE bit is not set */
#ifndef INLINE_FUNCTIONS
BOOL
TestBit(
	unsigned int     bitNum,        // IN: number of the bit in 'bArray'
	BYTE            *bArray,        // IN: array containing the bits
	unsigned int     bytesInArray   // IN: size in bytes of 'bArray'
	)
{
    pAssert(bytesInArray > (bitNum >> 3));
    return((bArray[bitNum >> 3] & (1 << (bitNum & 7))) != 0);
}
#endif // INLINE_FUNCTIONS
/* 9.2.3.2 SetBit() */
/* This function will set the indicated bit in bArray. */
#ifndef INLINE_FUNCTIONS
void
SetBit(
       unsigned int     bitNum,        // IN: number of the bit in 'bArray'
       BYTE            *bArray,        // IN: array containing the bits
       unsigned int     bytesInArray   // IN: size in bytes of 'bArray'
       )
{
    pAssert(bytesInArray > (bitNum >> 3));
    bArray[bitNum >> 3] |= (1 << (bitNum & 7));
}
#endif // INLINE_FUNCTIONS
/* 9.2.3.3 ClearBit() */
/* This function will clear the indicated bit in bArray. */
#ifndef INLINE_FUNCTIONS
void
ClearBit(
	 unsigned int     bitNum,        // IN: number of the bit in 'bArray'.
	 BYTE            *bArray,        // IN: array containing the bits
	 unsigned int     bytesInArray   // IN: size in bytes of 'bArray'
	 )
{
    pAssert(bytesInArray > (bitNum >> 3));
    bArray[bitNum >> 3] &= ~(1 << (bitNum & 7));
}
#endif // INLINE_FUNCTIONS
