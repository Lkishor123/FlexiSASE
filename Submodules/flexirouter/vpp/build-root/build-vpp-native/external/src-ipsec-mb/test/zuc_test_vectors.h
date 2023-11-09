/*****************************************************************************
 Copyright (c) 2009-2020, Intel Corporation

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

#ifndef __ZUC_TEST_VECTORS_H__
#define __ZUC_TEST_VECTORS_H__

#define MAX_BUFFER_LENGTH_IN_BITS 5670 /* biggest test is EIA test 5 */
#define MAX_BUFFER_LENGTH_IN_BYTES ((MAX_BUFFER_LENGTH_IN_BITS) + 7)/8
#define NUM_ZUC_ALG_TESTS 3
#define NUM_ZUC_EEA3_TESTS 5
#define NUM_ZUC_EIA3_TESTS 10
#define ZUC_KEY_LEN_IN_BYTES 16
#define ZUC_IV_LEN_IN_BYTES 16
#define ZUC_DIGEST_LEN 4

typedef struct testZUC_vectors_t {
	uint8_t CK[16];
	uint8_t IV[16];
	uint32_t Z[2];

} testZUC_vectors_t;
typedef struct test128EEA3_vectors_t {
	uint8_t CK[16];
	uint32_t count;
	uint8_t Bearer;
	uint8_t Direction;
	uint32_t length_in_bits;
	uint8_t plaintext[MAX_BUFFER_LENGTH_IN_BYTES];
	uint8_t ciphertext[MAX_BUFFER_LENGTH_IN_BYTES];
} test128EEA_vectors_t;

typedef struct test128EIA3_vectors_t {
	uint8_t CK[16];
	uint32_t count;
	uint8_t Bearer;
	uint8_t Direction;
	uint32_t length_in_bits;
	uint8_t message[MAX_BUFFER_LENGTH_IN_BYTES];
	uint8_t mac[4];
} test128EIA_vectors_t;

/*
 * ZUC algorithm tests from 3GPP Document3: Implementator's Test Data.
 * Version 1.1 (4th Jan. 2011).
 */
const struct testZUC_vectors_t testZUC_vectors[] = {
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x27BEDE74, 0x018082DA}
	},
	{
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x0657CFA0, 0x7096398B}
	},
	{
		{0x3D, 0x4C, 0x4B, 0xE9, 0x6A, 0x82, 0xFD, 0xAE,
		 0xB5, 0x8F, 0x64, 0x1D, 0xB1, 0x7B, 0x45, 0x5B},
		{0x84, 0x31, 0x9A, 0xA8, 0xDE, 0x69, 0x15, 0xCA,
		 0x1F, 0x6B, 0xDA, 0x6B, 0xFB, 0xD8, 0xC7, 0x66},
		{0x14F1C272, 0x3279C419}
	},
	{
		{0x4D, 0x32, 0x0B, 0xFA, 0xD4, 0xC2, 0x85, 0xBF,
		 0xD6, 0xB8, 0xBD, 0x00, 0xF3, 0x9D, 0x8B, 0x41},
		{0x52, 0x95, 0x9D, 0xAB, 0xA0, 0xBF, 0x17, 0x6E,
		 0xCE, 0x2D, 0xC3, 0x15, 0x04, 0x9E, 0xB5, 0x74},
		{0xED4400E7, 0x0633E5C5}
	},
};
const struct test128EEA3_vectors_t testEEA3_vectors[] = {
	/* TestSet1*/
	{
		{0x17, 0x3D, 0x14, 0xBA, 0x50, 0x03, 0x73, 0x1D,
		 0x7A, 0x60, 0x04, 0x94, 0x70, 0xF0, 0x0A, 0x29},
		0x66035492,
		0x0F,
		0x0,
		193,
	/* plaintext*/
		{0x6C, 0xF6, 0x53, 0x40, 0x73, 0x55, 0x52, 0xAB,
		 0x0C, 0x97, 0x52, 0xFA, 0x6F, 0x90, 0x25, 0xFE,
		 0x0B, 0xD6, 0x75, 0xD9, 0x00, 0x58, 0x75, 0xB2,
		 0x00, 0x00, 0x00, 0x00},
	/*ciphertext*/
		{0xA6, 0xC8, 0x5F, 0xC6, 0x6A, 0xFB, 0x85, 0x33,
		 0xAA, 0xFC, 0x25, 0x18, 0xDF, 0xE7, 0x84, 0x94,
		 0x0E, 0xE1, 0xE4, 0xB0, 0x30, 0x23, 0x8C, 0xC8,
		 0x00, 0x00, 0x00, 0x00}
	},
	/*TestSet2*/
	{
		{0xE5, 0xBD, 0x3E, 0xA0, 0xEB, 0x55, 0xAD, 0xE8,
		 0x66, 0xC6, 0xAC, 0x58, 0xBD, 0x54, 0x30, 0x2A},
		0x56823,
		0x18,
		0x1,
		800,
	/*plaintext*/
		{0x14, 0xA8, 0xEF, 0x69, 0x3D, 0x67, 0x85, 0x07,
		 0xBB, 0xE7, 0x27, 0x0A, 0x7F, 0x67, 0xFF, 0x50,
		 0x06, 0xC3, 0x52, 0x5B, 0x98, 0x07, 0xE4, 0x67,
		 0xC4, 0xE5, 0x60, 0x00, 0xBA, 0x33, 0x8F, 0x5D,
		 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22,
		 0x46, 0xC8, 0x0D, 0x3B, 0x38, 0xF0, 0x7F, 0x4B,
		 0xE2, 0xD8, 0xFF, 0x58, 0x05, 0xF5, 0x13, 0x22,
		 0x29, 0xBD, 0xE9, 0x3B, 0xBB, 0xDC, 0xAF, 0x38,
		 0x2B, 0xF1, 0xEE, 0x97, 0x2F, 0xBF, 0x99, 0x77,
		 0xBA, 0xDA, 0x89, 0x45, 0x84, 0x7A, 0x2A, 0x6C,
		 0x9A, 0xD3, 0x4A, 0x66, 0x75, 0x54, 0xE0, 0x4D,
		 0x1F, 0x7F, 0xA2, 0xC3, 0x32, 0x41, 0xBD, 0x8F,
		 0x01, 0xBA, 0x22, 0x0D},
	/*ciphertext*/
		{0x13, 0x1D, 0x43, 0xE0, 0xDE, 0xA1, 0xBE, 0x5C,
		 0x5A, 0x1B, 0xFD, 0x97, 0x1D, 0x85, 0x2C, 0xBF,
		 0x71, 0x2D, 0x7B, 0x4F, 0x57, 0x96, 0x1F, 0xEA,
		 0x32, 0x08, 0xAF, 0xA8, 0xBC, 0xA4, 0x33, 0xF4,
		 0x56, 0xAD, 0x09, 0xC7, 0x41, 0x7E, 0x58, 0xBC,
		 0x69, 0xCF, 0x88, 0x66, 0xD1, 0x35, 0x3F, 0x74,
		 0x86, 0x5E, 0x80, 0x78, 0x1D, 0x20, 0x2D, 0xFB,
		 0x3E, 0xCF, 0xF7, 0xFC, 0xBC, 0x3B, 0x19, 0x0F,
		 0xE8, 0x2A, 0x20, 0x4E, 0xD0, 0xE3, 0x50, 0xFC,
		 0x0F, 0x6F, 0x26, 0x13, 0xB2, 0xF2, 0xBC, 0xA6,
		 0xDF, 0x5A, 0x47, 0x3A, 0x57, 0xA4, 0xA0, 0x0D,
		 0x98, 0x5E, 0xBA, 0xD8, 0x80, 0xD6, 0xF2, 0x38,
		 0x64, 0xA0, 0x7B, 0x01}
	},
	/*TestSet3*/
	{
		{0xD4, 0x55, 0x2A, 0x8F, 0xD6, 0xE6, 0x1C, 0xC8,
		 0x1A, 0x20, 0x09, 0x14, 0x1A, 0x29, 0xC1, 0x0B},
		0x76452EC1,
		0x2,
		0x1,
		1570,
		/* plaintext*/
		{0x38, 0xF0, 0x7F, 0x4B, 0xE2, 0xD8, 0xFF, 0x58,
		 0x05, 0xF5, 0x13, 0x22, 0x29, 0xBD, 0xE9, 0x3B,
		 0xBB, 0xDC, 0xAF, 0x38, 0x2B, 0xF1, 0xEE, 0x97,
		 0x2F, 0xBF, 0x99, 0x77, 0xBA, 0xDA, 0x89, 0x45,
		 0x84, 0x7A, 0x2A, 0x6C, 0x9A, 0xD3, 0x4A, 0x66,
		 0x75, 0x54, 0xE0, 0x4D, 0x1F, 0x7F, 0xA2, 0xC3,
		 0x32, 0x41, 0xBD, 0x8F, 0x01, 0xBA, 0x22, 0x0D,
		 0x3C, 0xA4, 0xEC, 0x41, 0xE0, 0x74, 0x59, 0x5F,
		 0x54, 0xAE, 0x2B, 0x45, 0x4F, 0xD9, 0x71, 0x43,
		 0x20, 0x43, 0x60, 0x19, 0x65, 0xCC, 0xA8, 0x5C,
		 0x24, 0x17, 0xED, 0x6C, 0xBE, 0xC3, 0xBA, 0xDA,
		 0x84, 0xFC, 0x8A, 0x57, 0x9A, 0xEA, 0x78, 0x37,
		 0xB0, 0x27, 0x11, 0x77, 0x24, 0x2A, 0x64, 0xDC,
		 0x0A, 0x9D, 0xE7, 0x1A, 0x8E, 0xDE, 0xE8, 0x6C,
		 0xA3, 0xD4, 0x7D, 0x03, 0x3D, 0x6B, 0xF5, 0x39,
		 0x80, 0x4E, 0xCA, 0x86, 0xC5, 0x84, 0xA9, 0x05,
		 0x2D, 0xE4, 0x6A, 0xD3, 0xFC, 0xED, 0x65, 0x54,
		 0x3B, 0xD9, 0x02, 0x07, 0x37, 0x2B, 0x27, 0xAF,
		 0xB7, 0x92, 0x34, 0xF5, 0xFF, 0x43, 0xEA, 0x87,
		 0x08, 0x20, 0xE2, 0xC2, 0xB7, 0x8A, 0x8A, 0xAE,
		 0x61, 0xCC, 0xE5, 0x2A, 0x05, 0x15, 0xE3, 0x48,
		 0xD1, 0x96, 0x66, 0x4A, 0x34, 0x56, 0xB1, 0x82,
		 0xA0, 0x7C, 0x40, 0x6E, 0x4A, 0x20, 0x79, 0x12,
		 0x71, 0xCF, 0xED, 0xA1, 0x65, 0xD5, 0x35, 0xEC,
		 0x5E, 0xA2, 0xD4, 0xDF, 0x40, 0x00, 0x00, 0x00},
		/*ciphertext*/
		{0x83, 0x83, 0xB0, 0x22, 0x9F, 0xCC, 0x0B, 0x9D,
		 0x22, 0x95, 0xEC, 0x41, 0xC9, 0x77, 0xE9, 0xC2,
		 0xBB, 0x72, 0xE2, 0x20, 0x37, 0x81, 0x41, 0xF9,
		 0xC8, 0x31, 0x8F, 0x3A, 0x27, 0x0D, 0xFB, 0xCD,
		 0xEE, 0x64, 0x11, 0xC2, 0xB3, 0x04, 0x4F, 0x17,
		 0x6D, 0xC6, 0xE0, 0x0F, 0x89, 0x60, 0xF9, 0x7A,
		 0xFA, 0xCD, 0x13, 0x1A, 0xD6, 0xA3, 0xB4, 0x9B,
		 0x16, 0xB7, 0xBA, 0xBC, 0xF2, 0xA5, 0x09, 0xEB,
		 0xB1, 0x6A, 0x75, 0xDC, 0xAB, 0x14, 0xFF, 0x27,
		 0x5D, 0xBE, 0xEE, 0xA1, 0xA2, 0xB1, 0x55, 0xF9,
		 0xD5, 0x2C, 0x26, 0x45, 0x2D, 0x01, 0x87, 0xC3,
		 0x10, 0xA4, 0xEE, 0x55, 0xBE, 0xAA, 0x78, 0xAB,
		 0x40, 0x24, 0x61, 0x5B, 0xA9, 0xF5, 0xD5, 0xAD,
		 0xC7, 0x72, 0x8F, 0x73, 0x56, 0x06, 0x71, 0xF0,
		 0x13, 0xE5, 0xE5, 0x50, 0x08, 0x5D, 0x32, 0x91,
		 0xDF, 0x7D, 0x5F, 0xEC, 0xED, 0xDE, 0xD5, 0x59,
		 0x64, 0x1B, 0x6C, 0x2F, 0x58, 0x52, 0x33, 0xBC,
		 0x71, 0xE9, 0x60, 0x2B, 0xD2, 0x30, 0x58, 0x55,
		 0xBB, 0xD2, 0x5F, 0xFA, 0x7F, 0x17, 0xEC, 0xBC,
		 0x04, 0x2D, 0xAA, 0xE3, 0x8C, 0x1F, 0x57, 0xAD,
		 0x8E, 0x8E, 0xBD, 0x37, 0x34, 0x6F, 0x71, 0xBE,
		 0xFD, 0xBB, 0x74, 0x32, 0xE0, 0xE0, 0xBB, 0x2C,
		 0xFC, 0x09, 0xBC, 0xD9, 0x65, 0x70, 0xCB, 0x0C,
		 0x0C, 0x39, 0xDF, 0x5E, 0x29, 0x29, 0x4E, 0x82,
		 0x70, 0x3A, 0x63, 0x7F, 0x80, 0x00, 0x00, 0x00}
	},
	/*TestSet4*/
	{
	{0xDB, 0x84, 0xB4, 0xFB, 0xCC, 0xDA, 0x56, 0x3B,
	 0x66, 0x22, 0x7B, 0xFE, 0x45, 0x6F, 0x0F, 0x77},
	 0xE4850FE1,
	 0x10,
	 0x1,
	 2798,
	 /*plaintext*/
	 {0xE5, 0x39, 0xF3, 0xB8, 0x97, 0x32, 0x40, 0xDA,
	  0x03, 0xF2, 0xB8, 0xAA, 0x05, 0xEE, 0x0A, 0x00,
	  0xDB, 0xAF, 0xC0, 0xE1, 0x82, 0x05, 0x5D, 0xFE,
	  0x3D, 0x73, 0x83, 0xD9, 0x2C, 0xEF, 0x40, 0xE9,
	  0x29, 0x28, 0x60, 0x5D, 0x52, 0xD0, 0x5F, 0x4F,
	  0x90, 0x18, 0xA1, 0xF1, 0x89, 0xAE, 0x39, 0x97,
	  0xCE, 0x19, 0x15, 0x5F, 0xB1, 0x22, 0x1D, 0xB8,
	  0xBB, 0x09, 0x51, 0xA8, 0x53, 0xAD, 0x85, 0x2C,
	  0xE1, 0x6C, 0xFF, 0x07, 0x38, 0x2C, 0x93, 0xA1,
	  0x57, 0xDE, 0x00, 0xDD, 0xB1, 0x25, 0xC7, 0x53,
	  0x9F, 0xD8, 0x50, 0x45, 0xE4, 0xEE, 0x07, 0xE0,
	  0xC4, 0x3F, 0x9E, 0x9D, 0x6F, 0x41, 0x4F, 0xC4,
	  0xD1, 0xC6, 0x29, 0x17, 0x81, 0x3F, 0x74, 0xC0,
	  0x0F, 0xC8, 0x3F, 0x3E, 0x2E, 0xD7, 0xC4, 0x5B,
	  0xA5, 0x83, 0x52, 0x64, 0xB4, 0x3E, 0x0B, 0x20,
	  0xAF, 0xDA, 0x6B, 0x30, 0x53, 0xBF, 0xB6, 0x42,
	  0x3B, 0x7F, 0xCE, 0x25, 0x47, 0x9F, 0xF5, 0xF1,
	  0x39, 0xDD, 0x9B, 0x5B, 0x99, 0x55, 0x58, 0xE2,
	  0xA5, 0x6B, 0xE1, 0x8D, 0xD5, 0x81, 0xCD, 0x01,
	  0x7C, 0x73, 0x5E, 0x6F, 0x0D, 0x0D, 0x97, 0xC4,
	  0xDD, 0xC1, 0xD1, 0xDA, 0x70, 0xC6, 0xDB, 0x4A,
	  0x12, 0xCC, 0x92, 0x77, 0x8E, 0x2F, 0xBB, 0xD6,
	  0xF3, 0xBA, 0x52, 0xAF, 0x91, 0xC9, 0xC6, 0xB6,
	  0x4E, 0x8D, 0xA4, 0xF7, 0xA2, 0xC2, 0x66, 0xD0,
	  0x2D, 0x00, 0x17, 0x53, 0xDF, 0x08, 0x96, 0x03,
	  0x93, 0xC5, 0xD5, 0x68, 0x88, 0xBF, 0x49, 0xEB,
	  0x5C, 0x16, 0xD9, 0xA8, 0x04, 0x27, 0xA4, 0x16,
	  0xBC, 0xB5, 0x97, 0xDF, 0x5B, 0xFE, 0x6F, 0x13,
	  0x89, 0x0A, 0x07, 0xEE, 0x13, 0x40, 0xE6, 0x47,
	  0x6B, 0x0D, 0x9A, 0xA8, 0xF8, 0x22, 0xAB, 0x0F,
	  0xD1, 0xAB, 0x0D, 0x20, 0x4F, 0x40, 0xB7, 0xCE,
	  0x6F, 0x2E, 0x13, 0x6E, 0xB6, 0x74, 0x85, 0xE5,
	  0x07, 0x80, 0x4D, 0x50, 0x45, 0x88, 0xAD, 0x37,
	  0xFF, 0xD8, 0x16, 0x56, 0x8B, 0x2D, 0xC4, 0x03,
	  0x11, 0xDF, 0xB6, 0x54, 0xCD, 0xEA, 0xD4, 0x7E,
	  0x23, 0x85, 0xC3, 0x43, 0x62, 0x03, 0xDD, 0x83,
	  0x6F, 0x9C, 0x64, 0xD9, 0x74, 0x62, 0xAD, 0x5D,
	  0xFA, 0x63, 0xB5, 0xCF, 0xE0, 0x8A, 0xCB, 0x95,
	  0x32, 0x86, 0x6F, 0x5C, 0xA7, 0x87, 0x56, 0x6F,
	  0xCA, 0x93, 0xE6, 0xB1, 0x69, 0x3E, 0xE1, 0x5C,
	  0xF6, 0xF7, 0xA2, 0xD6, 0x89, 0xD9, 0x74, 0x17,
	  0x98, 0xDC, 0x1C, 0x23, 0x8E, 0x1B, 0xE6, 0x50,
	  0x73, 0x3B, 0x18, 0xFB, 0x34, 0xFF, 0x88, 0x0E,
	  0x16, 0xBB, 0xD2, 0x1B, 0x47, 0xAC, 0x00, 0x00},
	/*ciphertext*/
	 {0x4B, 0xBF, 0xA9, 0x1B, 0xA2, 0x5D, 0x47, 0xDB,
	  0x9A, 0x9F, 0x19, 0x0D, 0x96, 0x2A, 0x19, 0xAB,
	  0x32, 0x39, 0x26, 0xB3, 0x51, 0xFB, 0xD3, 0x9E,
	  0x35, 0x1E, 0x05, 0xDA, 0x8B, 0x89, 0x25, 0xE3,
	  0x0B, 0x1C, 0xCE, 0x0D, 0x12, 0x21, 0x10, 0x10,
	  0x95, 0x81, 0x5C, 0xC7, 0xCB, 0x63, 0x19, 0x50,
	  0x9E, 0xC0, 0xD6, 0x79, 0x40, 0x49, 0x19, 0x87,
	  0xE1, 0x3F, 0x0A, 0xFF, 0xAC, 0x33, 0x2A, 0xA6,
	  0xAA, 0x64, 0x62, 0x6D, 0x3E, 0x9A, 0x19, 0x17,
	  0x51, 0x9E, 0x0B, 0x97, 0xB6, 0x55, 0xC6, 0xA1,
	  0x65, 0xE4, 0x4C, 0xA9, 0xFE, 0xAC, 0x07, 0x90,
	  0xD2, 0xA3, 0x21, 0xAD, 0x3D, 0x86, 0xB7, 0x9C,
	  0x51, 0x38, 0x73, 0x9F, 0xA3, 0x8D, 0x88, 0x7E,
	  0xC7, 0xDE, 0xF4, 0x49, 0xCE, 0x8A, 0xBD, 0xD3,
	  0xE7, 0xF8, 0xDC, 0x4C, 0xA9, 0xE7, 0xB7, 0x33,
	  0x14, 0xAD, 0x31, 0x0F, 0x90, 0x25, 0xE6, 0x19,
	  0x46, 0xB3, 0xA5, 0x6D, 0xC6, 0x49, 0xEC, 0x0D,
	  0xA0, 0xD6, 0x39, 0x43, 0xDF, 0xF5, 0x92, 0xCF,
	  0x96, 0x2A, 0x7E, 0xFB, 0x2C, 0x85, 0x24, 0xE3,
	  0x5A, 0x2A, 0x6E, 0x78, 0x79, 0xD6, 0x26, 0x04,
	  0xEF, 0x26, 0x86, 0x95, 0xFA, 0x40, 0x03, 0x02,
	  0x7E, 0x22, 0xE6, 0x08, 0x30, 0x77, 0x52, 0x20,
	  0x64, 0xBD, 0x4A, 0x5B, 0x90, 0x6B, 0x5F, 0x53,
	  0x12, 0x74, 0xF2, 0x35, 0xED, 0x50, 0x6C, 0xFF,
	  0x01, 0x54, 0xC7, 0x54, 0x92, 0x8A, 0x0C, 0xE5,
	  0x47, 0x6F, 0x2C, 0xB1, 0x02, 0x0A, 0x12, 0x22,
	  0xD3, 0x2C, 0x14, 0x55, 0xEC, 0xAE, 0xF1, 0xE3,
	  0x68, 0xFB, 0x34, 0x4D, 0x17, 0x35, 0xBF, 0xBE,
	  0xDE, 0xB7, 0x1D, 0x0A, 0x33, 0xA2, 0xA5, 0x4B,
	  0x1D, 0xA5, 0xA2, 0x94, 0xE6, 0x79, 0x14, 0x4D,
	  0xDF, 0x11, 0xEB, 0x1A, 0x3D, 0xE8, 0xCF, 0x0C,
	  0xC0, 0x61, 0x91, 0x79, 0x74, 0xF3, 0x5C, 0x1D,
	  0x9C, 0xA0, 0xAC, 0x81, 0x80, 0x7F, 0x8F, 0xCC,
	  0xE6, 0x19, 0x9A, 0x6C, 0x77, 0x12, 0xDA, 0x86,
	  0x50, 0x21, 0xB0, 0x4C, 0xE0, 0x43, 0x95, 0x16,
	  0xF1, 0xA5, 0x26, 0xCC, 0xDA, 0x9F, 0xD9, 0xAB,
	  0xBD, 0x53, 0xC3, 0xA6, 0x84, 0xF9, 0xAE, 0x1E,
	  0x7E, 0xE6, 0xB1, 0x1D, 0xA1, 0x38, 0xEA, 0x82,
	  0x6C, 0x55, 0x16, 0xB5, 0xAA, 0xDF, 0x1A, 0xBB,
	  0xE3, 0x6F, 0xA7, 0xFF, 0xF9, 0x2E, 0x3A, 0x11,
	  0x76, 0x06, 0x4E, 0x8D, 0x95, 0xF2, 0xE4, 0x88,
	  0x2B, 0x55, 0x00, 0xB9, 0x32, 0x28, 0xB2, 0x19,
	  0x4A, 0x47, 0x5C, 0x1A, 0x27, 0xF6, 0x3F, 0x9F,
	  0xFD, 0x26, 0x49, 0x89, 0xA1, 0xBC, 0x00, 0x00}
	},
	/*TestSet5*/
	{
	{0xE1, 0x3F, 0xED, 0x21, 0xB4, 0x6E, 0x4E, 0x7E,
	 0xC3, 0x12, 0x53, 0xB2, 0xBB, 0x17, 0xB3, 0xE0},
	0x2738CDAA,
	0x1A,
	0x0,
	4019,
	/*plaintext*/
	{0x8D, 0x74, 0xE2, 0x0D, 0x54, 0x89, 0x4E, 0x06,
	 0xD3, 0xCB, 0x13, 0xCB, 0x39, 0x33, 0x06, 0x5E,
	 0x86, 0x74, 0xBE, 0x62, 0xAD, 0xB1, 0xC7, 0x2B,
	 0x3A, 0x64, 0x69, 0x65, 0xAB, 0x63, 0xCB, 0x7B,
	 0x78, 0x54, 0xDF, 0xDC, 0x27, 0xE8, 0x49, 0x29,
	 0xF4, 0x9C, 0x64, 0xB8, 0x72, 0xA4, 0x90, 0xB1,
	 0x3F, 0x95, 0x7B, 0x64, 0x82, 0x7E, 0x71, 0xF4,
	 0x1F, 0xBD, 0x42, 0x69, 0xA4, 0x2C, 0x97, 0xF8,
	 0x24, 0x53, 0x70, 0x27, 0xF8, 0x6E, 0x9F, 0x4A,
	 0xD8, 0x2D, 0x1D, 0xF4, 0x51, 0x69, 0x0F, 0xDD,
	 0x98, 0xB6, 0xD0, 0x3F, 0x3A, 0x0E, 0xBE, 0x3A,
	 0x31, 0x2D, 0x6B, 0x84, 0x0B, 0xA5, 0xA1, 0x82,
	 0x0B, 0x2A, 0x2C, 0x97, 0x09, 0xC0, 0x90, 0xD2,
	 0x45, 0xED, 0x26, 0x7C, 0xF8, 0x45, 0xAE, 0x41,
	 0xFA, 0x97, 0x5D, 0x33, 0x33, 0xAC, 0x30, 0x09,
	 0xFD, 0x40, 0xEB, 0xA9, 0xEB, 0x5B, 0x88, 0x57,
	 0x14, 0xB7, 0x68, 0xB6, 0x97, 0x13, 0x8B, 0xAF,
	 0x21, 0x38, 0x0E, 0xCA, 0x49, 0xF6, 0x44, 0xD4,
	 0x86, 0x89, 0xE4, 0x21, 0x57, 0x60, 0xB9, 0x06,
	 0x73, 0x9F, 0x0D, 0x2B, 0x3F, 0x09, 0x11, 0x33,
	 0xCA, 0x15, 0xD9, 0x81, 0xCB, 0xE4, 0x01, 0xBA,
	 0xF7, 0x2D, 0x05, 0xAC, 0xE0, 0x5C, 0xCC, 0xB2,
	 0xD2, 0x97, 0xF4, 0xEF, 0x6A, 0x5F, 0x58, 0xD9,
	 0x12, 0x46, 0xCF, 0xA7, 0x72, 0x15, 0xB8, 0x92,
	 0xAB, 0x44, 0x1D, 0x52, 0x78, 0x45, 0x27, 0x95,
	 0xCC, 0xB7, 0xF5, 0xD7, 0x90, 0x57, 0xA1, 0xC4,
	 0xF7, 0x7F, 0x80, 0xD4, 0x6D, 0xB2, 0x03, 0x3C,
	 0xB7, 0x9B, 0xED, 0xF8, 0xE6, 0x05, 0x51, 0xCE,
	 0x10, 0xC6, 0x67, 0xF6, 0x2A, 0x97, 0xAB, 0xAF,
	 0xAB, 0xBC, 0xD6, 0x77, 0x20, 0x18, 0xDF, 0x96,
	 0xA2, 0x82, 0xEA, 0x73, 0x7C, 0xE2, 0xCB, 0x33,
	 0x12, 0x11, 0xF6, 0x0D, 0x53, 0x54, 0xCE, 0x78,
	 0xF9, 0x91, 0x8D, 0x9C, 0x20, 0x6C, 0xA0, 0x42,
	 0xC9, 0xB6, 0x23, 0x87, 0xDD, 0x70, 0x96, 0x04,
	 0xA5, 0x0A, 0xF1, 0x6D, 0x8D, 0x35, 0xA8, 0x90,
	 0x6B, 0xE4, 0x84, 0xCF, 0x2E, 0x74, 0xA9, 0x28,
	 0x99, 0x40, 0x36, 0x43, 0x53, 0x24, 0x9B, 0x27,
	 0xB4, 0xC9, 0xAE, 0x29, 0xED, 0xDF, 0xC7, 0xDA,
	 0x64, 0x18, 0x79, 0x1A, 0x4E, 0x7B, 0xAA, 0x06,
	 0x60, 0xFA, 0x64, 0x51, 0x1F, 0x2D, 0x68, 0x5C,
	 0xC3, 0xA5, 0xFF, 0x70, 0xE0, 0xD2, 0xB7, 0x42,
	 0x92, 0xE3, 0xB8, 0xA0, 0xCD, 0x6B, 0x04, 0xB1,
	 0xC7, 0x90, 0xB8, 0xEA, 0xD2, 0x70, 0x37, 0x08,
	 0x54, 0x0D, 0xEA, 0x2F, 0xC0, 0x9C, 0x3D, 0xA7,
	 0x70, 0xF6, 0x54, 0x49, 0xE8, 0x4D, 0x81, 0x7A,
	 0x4F, 0x55, 0x10, 0x55, 0xE1, 0x9A, 0xB8, 0x50,
	 0x18, 0xA0, 0x02, 0x8B, 0x71, 0xA1, 0x44, 0xD9,
	 0x67, 0x91, 0xE9, 0xA3, 0x57, 0x79, 0x33, 0x50,
	 0x4E, 0xEE, 0x00, 0x60, 0x34, 0x0C, 0x69, 0xD2,
	 0x74, 0xE1, 0xBF, 0x9D, 0x80, 0x5D, 0xCB, 0xCC,
	 0x1A, 0x6F, 0xAA, 0x97, 0x68, 0x00, 0xB6, 0xFF,
	 0x2B, 0x67, 0x1D, 0xC4, 0x63, 0x65, 0x2F, 0xA8,
	 0xA3, 0x3E, 0xE5, 0x09, 0x74, 0xC1, 0xC2, 0x1B,
	 0xE0, 0x1E, 0xAB, 0xB2, 0x16, 0x74, 0x30, 0x26,
	 0x9D, 0x72, 0xEE, 0x51, 0x1C, 0x9D, 0xDE, 0x30,
	 0x79, 0x7C, 0x9A, 0x25, 0xD8, 0x6C, 0xE7, 0x4F,
	 0x5B, 0x96, 0x1B, 0xE5, 0xFD, 0xFB, 0x68, 0x07,
	 0x81, 0x40, 0x39, 0xE7, 0x13, 0x76, 0x36, 0xBD,
	 0x1D, 0x7F, 0xA9, 0xE0, 0x9E, 0xFD, 0x20, 0x07,
	 0x50, 0x59, 0x06, 0xA5, 0xAC, 0x45, 0xDF, 0xDE,
	 0xED, 0x77, 0x57, 0xBB, 0xEE, 0x74, 0x57, 0x49,
	 0xC2, 0x96, 0x33, 0x35, 0x0B, 0xEE, 0x0E, 0xA6,
	 0xF4, 0x09, 0xDF, 0x45, 0x80, 0x16, 0x00, 0x00},
	/*ciphertext*/
	{0x94, 0xEA, 0xA4, 0xAA, 0x30, 0xA5, 0x71, 0x37,
	 0xDD, 0xF0, 0x9B, 0x97, 0xB2, 0x56, 0x18, 0xA2,
	 0x0A, 0x13, 0xE2, 0xF1, 0x0F, 0xA5, 0xBF, 0x81,
	 0x61, 0xA8, 0x79, 0xCC, 0x2A, 0xE7, 0x97, 0xA6,
	 0xB4, 0xCF, 0x2D, 0x9D, 0xF3, 0x1D, 0xEB, 0xB9,
	 0x90, 0x5C, 0xCF, 0xEC, 0x97, 0xDE, 0x60, 0x5D,
	 0x21, 0xC6, 0x1A, 0xB8, 0x53, 0x1B, 0x7F, 0x3C,
	 0x9D, 0xA5, 0xF0, 0x39, 0x31, 0xF8, 0xA0, 0x64,
	 0x2D, 0xE4, 0x82, 0x11, 0xF5, 0xF5, 0x2F, 0xFE,
	 0xA1, 0x0F, 0x39, 0x2A, 0x04, 0x76, 0x69, 0x98,
	 0x5D, 0xA4, 0x54, 0xA2, 0x8F, 0x08, 0x09, 0x61,
	 0xA6, 0xC2, 0xB6, 0x2D, 0xAA, 0x17, 0xF3, 0x3C,
	 0xD6, 0x0A, 0x49, 0x71, 0xF4, 0x8D, 0x2D, 0x90,
	 0x93, 0x94, 0xA5, 0x5F, 0x48, 0x11, 0x7A, 0xCE,
	 0x43, 0xD7, 0x08, 0xE6, 0xB7, 0x7D, 0x3D, 0xC4,
	 0x6D, 0x8B, 0xC0, 0x17, 0xD4, 0xD1, 0xAB, 0xB7,
	 0x7B, 0x74, 0x28, 0xC0, 0x42, 0xB0, 0x6F, 0x2F,
	 0x99, 0xD8, 0xD0, 0x7C, 0x98, 0x79, 0xD9, 0x96,
	 0x00, 0x12, 0x7A, 0x31, 0x98, 0x5F, 0x10, 0x99,
	 0xBB, 0xD7, 0xD6, 0xC1, 0x51, 0x9E, 0xDE, 0x8F,
	 0x5E, 0xEB, 0x4A, 0x61, 0x0B, 0x34, 0x9A, 0xC0,
	 0x1E, 0xA2, 0x35, 0x06, 0x91, 0x75, 0x6B, 0xD1,
	 0x05, 0xC9, 0x74, 0xA5, 0x3E, 0xDD, 0xB3, 0x5D,
	 0x1D, 0x41, 0x00, 0xB0, 0x12, 0xE5, 0x22, 0xAB,
	 0x41, 0xF4, 0xC5, 0xF2, 0xFD, 0xE7, 0x6B, 0x59,
	 0xCB, 0x8B, 0x96, 0xD8, 0x85, 0xCF, 0xE4, 0x08,
	 0x0D, 0x13, 0x28, 0xA0, 0xD6, 0x36, 0xCC, 0x0E,
	 0xDC, 0x05, 0x80, 0x0B, 0x76, 0xAC, 0xCA, 0x8F,
	 0xEF, 0x67, 0x20, 0x84, 0xD1, 0xF5, 0x2A, 0x8B,
	 0xBD, 0x8E, 0x09, 0x93, 0x32, 0x09, 0x92, 0xC7,
	 0xFF, 0xBA, 0xE1, 0x7C, 0x40, 0x84, 0x41, 0xE0,
	 0xEE, 0x88, 0x3F, 0xC8, 0xA8, 0xB0, 0x5E, 0x22,
	 0xF5, 0xFF, 0x7F, 0x8D, 0x1B, 0x48, 0xC7, 0x4C,
	 0x46, 0x8C, 0x46, 0x7A, 0x02, 0x8F, 0x09, 0xFD,
	 0x7C, 0xE9, 0x11, 0x09, 0xA5, 0x70, 0xA2, 0xD5,
	 0xC4, 0xD5, 0xF4, 0xFA, 0x18, 0xC5, 0xDD, 0x3E,
	 0x45, 0x62, 0xAF, 0xE2, 0x4E, 0xF7, 0x71, 0x90,
	 0x1F, 0x59, 0xAF, 0x64, 0x58, 0x98, 0xAC, 0xEF,
	 0x08, 0x8A, 0xBA, 0xE0, 0x7E, 0x92, 0xD5, 0x2E,
	 0xB2, 0xDE, 0x55, 0x04, 0x5B, 0xB1, 0xB7, 0xC4,
	 0x16, 0x4E, 0xF2, 0xD7, 0xA6, 0xCA, 0xC1, 0x5E,
	 0xEB, 0x92, 0x6D, 0x7E, 0xA2, 0xF0, 0x8B, 0x66,
	 0xE1, 0xF7, 0x59, 0xF3, 0xAE, 0xE4, 0x46, 0x14,
	 0x72, 0x5A, 0xA3, 0xC7, 0x48, 0x2B, 0x30, 0x84,
	 0x4C, 0x14, 0x3F, 0xF8, 0x5B, 0x53, 0xF1, 0xE5,
	 0x83, 0xC5, 0x01, 0x25, 0x7D, 0xDD, 0xD0, 0x96,
	 0xB8, 0x12, 0x68, 0xDA, 0xA3, 0x03, 0xF1, 0x72,
	 0x34, 0xC2, 0x33, 0x35, 0x41, 0xF0, 0xBB, 0x8E,
	 0x19, 0x06, 0x48, 0xC5, 0x80, 0x7C, 0x86, 0x6D,
	 0x71, 0x93, 0x22, 0x86, 0x09, 0xAD, 0xB9, 0x48,
	 0x68, 0x6F, 0x7D, 0xE2, 0x94, 0xA8, 0x02, 0xCC,
	 0x38, 0xF7, 0xFE, 0x52, 0x08, 0xF5, 0xEA, 0x31,
	 0x96, 0xD0, 0x16, 0x7B, 0x9B, 0xDD, 0x02, 0xF0,
	 0xD2, 0xA5, 0x22, 0x1C, 0xA5, 0x08, 0xF8, 0x93,
	 0xAF, 0x5C, 0x4B, 0x4B, 0xB9, 0xF4, 0xF5, 0x20,
	 0xFD, 0x84, 0x28, 0x9B, 0x3D, 0xBE, 0x7E, 0x61,
	 0x49, 0x7A, 0x7E, 0x2A, 0x58, 0x40, 0x37, 0xEA,
	 0x63, 0x7B, 0x69, 0x81, 0x12, 0x71, 0x74, 0xAF,
	 0x57, 0xB4, 0x71, 0xDF, 0x4B, 0x27, 0x68, 0xFD,
	 0x79, 0xC1, 0x54, 0x0F, 0xB3, 0xED, 0xF2, 0xEA,
	 0x22, 0xCB, 0x69, 0xBE, 0xC0, 0xCF, 0x8D, 0x93,
	 0x3D, 0x9C, 0x6F, 0xDD, 0x64, 0x5E, 0x85, 0x05,
	 0x91, 0xCC, 0xA3, 0xD6, 0x2C, 0x0C, 0xC0, 0x00}
	}
};
const struct test128EIA3_vectors_t testEIA3_vectors[] = {
	{
	/*Test 1*/
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		0x00000000,
		0x0,
		0x0,
		1,
		{0x00, 0x00, 0x00, 0x00},
		{0xC8, 0xA9, 0x59, 0x5E}
	},
	{
	/*Test 2*/
		{0x47, 0x05, 0x41, 0x25, 0x56, 0x1e, 0xb2, 0xdd,
		 0xa9, 0x40, 0x59, 0xda, 0x05, 0x09, 0x78, 0x50},
		0x561EB2DD,
		0x14,
		0,
		90,
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00},
		{0x67, 0x19, 0xA0, 0x88}
	},
	/*Test 3*/
	{
		{0xC9, 0xE6, 0xCE, 0xC4, 0x60, 0x7C, 0x72, 0xDB,
		 0x00, 0x0A, 0xEF, 0xA8, 0x83, 0x85, 0xAB, 0x0A},
		0xA94059DA,
		0xA,
		0x1,
		577,
		{0x98, 0x3B, 0x41, 0xD4, 0x7D, 0x78, 0x0C, 0x9E,
		 0x1A, 0xD1, 0x1D, 0x7E, 0xB7, 0x03, 0x91, 0xB1,
		 0xDE, 0x0B, 0x35, 0xDA, 0x2D, 0xC6, 0x2F, 0x83,
		 0xE7, 0xB7, 0x8D, 0x63, 0x06, 0xCA, 0x0E, 0xA0,
		 0x7E, 0x94, 0x1B, 0x7B, 0xE9, 0x13, 0x48, 0xF9,
		 0xFC, 0xB1, 0x70, 0xE2, 0x21, 0x7F, 0xEC, 0xD9,
		 0x7F, 0x9F, 0x68, 0xAD, 0xB1, 0x6E, 0x5D, 0x7D,
		 0x21, 0xE5, 0x69, 0xD2, 0x80, 0xED, 0x77, 0x5C,
		 0xEB, 0xDE, 0x3F, 0x40, 0x93, 0xC5, 0x38, 0x81,
		 0x00, 0x00, 0x00, 0x00},
		{0xFA, 0xE8, 0xFF, 0x0B}
	},
	/*Test 4*/
	{
		{0xc8, 0xa4, 0x82, 0x62, 0xd0, 0xc2, 0xe2, 0xba,
		 0xc4, 0xb9, 0x6e, 0xf7, 0x7e, 0x80, 0xca, 0x59},
		0x5097850,
		0x10,
		0x1,
		2079,
		{0xb5, 0x46, 0x43, 0x0b, 0xf8, 0x7b, 0x4f, 0x1e,
		 0xe8, 0x34, 0x70, 0x4c, 0xd6, 0x95, 0x1c, 0x36,
		 0xe2, 0x6f, 0x10, 0x8c, 0xf7, 0x31, 0x78, 0x8f,
		 0x48, 0xdc, 0x34, 0xf1, 0x67, 0x8c, 0x05, 0x22,
		 0x1c, 0x8f, 0xa7, 0xff, 0x2f, 0x39, 0xf4, 0x77,
		 0xe7, 0xe4, 0x9e, 0xf6, 0x0a, 0x4e, 0xc2, 0xc3,
		 0xde, 0x24, 0x31, 0x2a, 0x96, 0xaa, 0x26, 0xe1,
		 0xcf, 0xba, 0x57, 0x56, 0x38, 0x38, 0xb2, 0x97,
		 0xf4, 0x7e, 0x85, 0x10, 0xc7, 0x79, 0xfd, 0x66,
		 0x54, 0xb1, 0x43, 0x38, 0x6f, 0xa6, 0x39, 0xd3,
		 0x1e, 0xdb, 0xd6, 0xc0, 0x6e, 0x47, 0xd1, 0x59,
		 0xd9, 0x43, 0x62, 0xf2, 0x6a, 0xee, 0xed, 0xee,
		 0x0e, 0x4f, 0x49, 0xd9, 0xbf, 0x84, 0x12, 0x99,
		 0x54, 0x15, 0xbf, 0xad, 0x56, 0xee, 0x82, 0xd1,
		 0xca, 0x74, 0x63, 0xab, 0xf0, 0x85, 0xb0, 0x82,
		 0xb0, 0x99, 0x04, 0xd6, 0xd9, 0x90, 0xd4, 0x3c,
		 0xf2, 0xe0, 0x62, 0xf4, 0x08, 0x39, 0xd9, 0x32,
		 0x48, 0xb1, 0xeb, 0x92, 0xcd, 0xfe, 0xd5, 0x30,
		 0x0b, 0xc1, 0x48, 0x28, 0x04, 0x30, 0xb6, 0xd0,
		 0xca, 0xa0, 0x94, 0xb6, 0xec, 0x89, 0x11, 0xab,
		 0x7d, 0xc3, 0x68, 0x24, 0xb8, 0x24, 0xdc, 0x0a,
		 0xf6, 0x68, 0x2b, 0x09, 0x35, 0xfd, 0xe7, 0xb4,
		 0x92, 0xa1, 0x4d, 0xc2, 0xf4, 0x36, 0x48, 0x03,
		 0x8d, 0xa2, 0xcf, 0x79, 0x17, 0x0d, 0x2d, 0x50,
		 0x13, 0x3f, 0xd4, 0x94, 0x16, 0xcb, 0x6e, 0x33,
		 0xbe, 0xa9, 0x0b, 0x8b, 0xf4, 0x55, 0x9b, 0x03,
		 0x73, 0x2a, 0x01, 0xea, 0x29, 0x0e, 0x6d, 0x07,
		 0x4f, 0x79, 0xbb, 0x83, 0xc1, 0x0e, 0x58, 0x00,
		 0x15, 0xcc, 0x1a, 0x85, 0xb3, 0x6b, 0x55, 0x01,
		 0x04, 0x6e, 0x9c, 0x4b, 0xdc, 0xae, 0x51, 0x35,
		 0x69, 0x0b, 0x86, 0x66, 0xbd, 0x54, 0xb7, 0xa7,
		 0x03, 0xea, 0x7b, 0x6f, 0x22, 0x0a, 0x54, 0x69,
		 0xa5, 0x68, 0x02, 0x7e},
		{0x00, 0x4A, 0xC4, 0xD6}
	},
	/*Test 5*/
	{
		{0x6B, 0x8B, 0x08, 0xEE, 0x79, 0xE0, 0xB5, 0x98,
		 0x2D, 0x6D, 0x12, 0x8E, 0xA9, 0xF2, 0x20, 0xCB},
		0x561EB2DD,
		0x1C,
		0x0,
		5670,
		{0x5B, 0xAD, 0x72, 0x47, 0x10, 0xBA, 0x1C, 0x56,
		 0xD5, 0xA3, 0x15, 0xF8, 0xD4, 0x0F, 0x6E, 0x09,
		 0x37, 0x80, 0xBE, 0x8E, 0x8D, 0xE0, 0x7B, 0x69,
		 0x92, 0x43, 0x20, 0x18, 0xE0, 0x8E, 0xD9, 0x6A,
		 0x57, 0x34, 0xAF, 0x8B, 0xAD, 0x8A, 0x57, 0x5D,
		 0x3A, 0x1F, 0x16, 0x2F, 0x85, 0x04, 0x5C, 0xC7,
		 0x70, 0x92, 0x55, 0x71, 0xD9, 0xF5, 0xB9, 0x4E,
		 0x45, 0x4A, 0x77, 0xC1, 0x6E, 0x72, 0x93, 0x6B,
		 0xF0, 0x16, 0xAE, 0x15, 0x74, 0x99, 0xF0, 0x54,
		 0x3B, 0x5D, 0x52, 0xCA, 0xA6, 0xDB, 0xEA, 0xB6,
		 0x97, 0xD2, 0xBB, 0x73, 0xE4, 0x1B, 0x80, 0x75,
		 0xDC, 0xE7, 0x9B, 0x4B, 0x86, 0x04, 0x4F, 0x66,
		 0x1D, 0x44, 0x85, 0xA5, 0x43, 0xDD, 0x78, 0x60,
		 0x6E, 0x04, 0x19, 0xE8, 0x05, 0x98, 0x59, 0xD3,
		 0xCB, 0x2B, 0x67, 0xCE, 0x09, 0x77, 0x60, 0x3F,
		 0x81, 0xFF, 0x83, 0x9E, 0x33, 0x18, 0x59, 0x54,
		 0x4C, 0xFB, 0xC8, 0xD0, 0x0F, 0xEF, 0x1A, 0x4C,
		 0x85, 0x10, 0xFB, 0x54, 0x7D, 0x6B, 0x06, 0xC6,
		 0x11, 0xEF, 0x44, 0xF1, 0xBC, 0xE1, 0x07, 0xCF,
		 0xA4, 0x5A, 0x06, 0xAA, 0xB3, 0x60, 0x15, 0x2B,
		 0x28, 0xDC, 0x1E, 0xBE, 0x6F, 0x7F, 0xE0, 0x9B,
		 0x05, 0x16, 0xF9, 0xA5, 0xB0, 0x2A, 0x1B, 0xD8,
		 0x4B, 0xB0, 0x18, 0x1E, 0x2E, 0x89, 0xE1, 0x9B,
		 0xD8, 0x12, 0x59, 0x30, 0xD1, 0x78, 0x68, 0x2F,
		 0x38, 0x62, 0xDC, 0x51, 0xB6, 0x36, 0xF0, 0x4E,
		 0x72, 0x0C, 0x47, 0xC3, 0xCE, 0x51, 0xAD, 0x70,
		 0xD9, 0x4B, 0x9B, 0x22, 0x55, 0xFB, 0xAE, 0x90,
		 0x65, 0x49, 0xF4, 0x99, 0xF8, 0xC6, 0xD3, 0x99,
		 0x47, 0xED, 0x5E, 0x5D, 0xF8, 0xE2, 0xDE, 0xF1,
		 0x13, 0x25, 0x3E, 0x7B, 0x08, 0xD0, 0xA7, 0x6B,
		 0x6B, 0xFC, 0x68, 0xC8, 0x12, 0xF3, 0x75, 0xC7,
		 0x9B, 0x8F, 0xE5, 0xFD, 0x85, 0x97, 0x6A, 0xA6,
		 0xD4, 0x6B, 0x4A, 0x23, 0x39, 0xD8, 0xAE, 0x51,
		 0x47, 0xF6, 0x80, 0xFB, 0xE7, 0x0F, 0x97, 0x8B,
		 0x38, 0xEF, 0xFD, 0x7B, 0x2F, 0x78, 0x66, 0xA2,
		 0x25, 0x54, 0xE1, 0x93, 0xA9, 0x4E, 0x98, 0xA6,
		 0x8B, 0x74, 0xBD, 0x25, 0xBB, 0x2B, 0x3F, 0x5F,
		 0xB0, 0xA5, 0xFD, 0x59, 0x88, 0x7F, 0x9A, 0xB6,
		 0x81, 0x59, 0xB7, 0x17, 0x8D, 0x5B, 0x7B, 0x67,
		 0x7C, 0xB5, 0x46, 0xBF, 0x41, 0xEA, 0xDC, 0xA2,
		 0x16, 0xFC, 0x10, 0x85, 0x01, 0x28, 0xF8, 0xBD,
		 0xEF, 0x5C, 0x8D, 0x89, 0xF9, 0x6A, 0xFA, 0x4F,
		 0xA8, 0xB5, 0x48, 0x85, 0x56, 0x5E, 0xD8, 0x38,
		 0xA9, 0x50, 0xFE, 0xE5, 0xF1, 0xC3, 0xB0, 0xA4,
		 0xF6, 0xFB, 0x71, 0xE5, 0x4D, 0xFD, 0x16, 0x9E,
		 0x82, 0xCE, 0xCC, 0x72, 0x66, 0xC8, 0x50, 0xE6,
		 0x7C, 0x5E, 0xF0, 0xBA, 0x96, 0x0F, 0x52, 0x14,
		 0x06, 0x0E, 0x71, 0xEB, 0x17, 0x2A, 0x75, 0xFC,
		 0x14, 0x86, 0x83, 0x5C, 0xBE, 0xA6, 0x53, 0x44,
		 0x65, 0xB0, 0x55, 0xC9, 0x6A, 0x72, 0xE4, 0x10,
		 0x52, 0x24, 0x18, 0x23, 0x25, 0xD8, 0x30, 0x41,
		 0x4B, 0x40, 0x21, 0x4D, 0xAA, 0x80, 0x91, 0xD2,
		 0xE0, 0xFB, 0x01, 0x0A, 0xE1, 0x5C, 0x6D, 0xE9,
		 0x08, 0x50, 0x97, 0x3B, 0xDF, 0x1E, 0x42, 0x3B,
		 0xE1, 0x48, 0xA2, 0x37, 0xB8, 0x7A, 0x0C, 0x9F,
		 0x34, 0xD4, 0xB4, 0x76, 0x05, 0xB8, 0x03, 0xD7,
		 0x43, 0xA8, 0x6A, 0x90, 0x39, 0x9A, 0x4A, 0xF3,
		 0x96, 0xD3, 0xA1, 0x20, 0x0A, 0x62, 0xF3, 0xD9,
		 0x50, 0x79, 0x62, 0xE8, 0xE5, 0xBE, 0xE6, 0xD3,
		 0xDA, 0x2B, 0xB3, 0xF7, 0x23, 0x76, 0x64, 0xAC,
		 0x7A, 0x29, 0x28, 0x23, 0x90, 0x0B, 0xC6, 0x35,
		 0x03, 0xB2, 0x9E, 0x80, 0xD6, 0x3F, 0x60, 0x67,
		 0xBF, 0x8E, 0x17, 0x16, 0xAC, 0x25, 0xBE, 0xBA,
		 0x35, 0x0D, 0xEB, 0x62, 0xA9, 0x9F, 0xE0, 0x31,
		 0x85, 0xEB, 0x4F, 0x69, 0x93, 0x7E, 0xCD, 0x38,
		 0x79, 0x41, 0xFD, 0xA5, 0x44, 0xBA, 0x67, 0xDB,
		 0x09, 0x11, 0x77, 0x49, 0x38, 0xB0, 0x18, 0x27,
		 0xBC, 0xC6, 0x9C, 0x92, 0xB3, 0xF7, 0x72, 0xA9,
		 0xD2, 0x85, 0x9E, 0xF0, 0x03, 0x39, 0x8B, 0x1F,
		 0x6B, 0xBA, 0xD7, 0xB5, 0x74, 0xF7, 0x98, 0x9A,
		 0x1D, 0x10, 0xB2, 0xDF, 0x79, 0x8E, 0x0D, 0xBF,
		 0x30, 0xD6, 0x58, 0x74, 0x64, 0xD2, 0x48, 0x78,
		 0xCD, 0x00, 0xC0, 0xEA, 0xEE, 0x8A, 0x1A, 0x0C,
		 0xC7, 0x53, 0xA2, 0x79, 0x79, 0xE1, 0x1B, 0x41,
		 0xDB, 0x1D, 0xE3, 0xD5, 0x03, 0x8A, 0xFA, 0xF4,
		 0x9F, 0x5C, 0x68, 0x2C, 0x37, 0x48, 0xD8, 0xA3,
		 0xA9, 0xEC, 0x54, 0xE6, 0xA3, 0x71, 0x27, 0x5F,
		 0x16, 0x83, 0x51, 0x0F, 0x8E, 0x4F, 0x90, 0x93,
		 0x8F, 0x9A, 0xB6, 0xE1, 0x34, 0xC2, 0xCF, 0xDF,
		 0x48, 0x41, 0xCB, 0xA8, 0x8E, 0x0C, 0xFF, 0x2B,
		 0x0B, 0xCC, 0x8E, 0x6A, 0xDC, 0xB7, 0x11, 0x09,
		 0xB5, 0x19, 0x8F, 0xEC, 0xF1, 0xBB, 0x7E, 0x5C,
		 0x53, 0x1A, 0xCA, 0x50, 0xA5, 0x6A, 0x8A, 0x3B,
		 0x6D, 0xE5, 0x98, 0x62, 0xD4, 0x1F, 0xA1, 0x13,
		 0xD9, 0xCD, 0x95, 0x78, 0x08, 0xF0, 0x85, 0x71,
		 0xD9, 0xA4, 0xBB, 0x79, 0x2A, 0xF2, 0x71, 0xF6,
		 0xCC, 0x6D, 0xBB, 0x8D, 0xC7, 0xEC, 0x36, 0xE3,
		 0x6B, 0xE1, 0xED, 0x30, 0x81, 0x64, 0xC3, 0x1C,
		 0x7C, 0x0A, 0xFC, 0x54, 0x1C},
		{0x0C, 0xA1, 0x27, 0x92}
	},
        /*Custom test 1*/
        {
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		0x01234567,
		0xA,
		0x0,
		63,
		{0x5B, 0xAD, 0x72, 0x47, 0x10, 0xBA, 0x1C, 0x56},
		{0x84, 0x9A, 0xCA, 0xDB}
	},
        /*Custom test 2*/
	{
		{0xC9, 0xE6, 0xCE, 0xC4, 0x60, 0x7C, 0x72, 0xDB,
		 0x00, 0x0A, 0xEF, 0xA8, 0x83, 0x85, 0xAB, 0x0A},
		0xA94059DA,
		0xA,
		0x1,
		62,
		{0x98, 0x3B, 0x41, 0xD4, 0x7D, 0x78, 0x0C, 0x9E,
		 0x1A, 0xD1, 0x1D, 0x7E, 0xB7, 0x03, 0x91, 0xB1},
		{0x81, 0x17, 0x55, 0x81}
	},
        /*Custom test 3*/
	{
		{0xC9, 0xE6, 0xCE, 0xC4, 0x60, 0x7C, 0x72, 0xDB,
		 0x00, 0x0A, 0xEF, 0xA8, 0x83, 0x85, 0xAB, 0x0A},
		0xA94059DA,
		0xA,
		0x0,
		512,
		{0x98, 0x3B, 0x41, 0xD4, 0x7D, 0x78, 0x0C, 0x9E,
		 0x1A, 0xD1, 0x1D, 0x7E, 0xB7, 0x03, 0x91, 0xB1,
                 0xDE, 0x0B, 0x35, 0xDA, 0x2D, 0xC6, 0x2F, 0x83,
		 0xE7, 0xB7, 0x8D, 0x63, 0x06, 0xCA, 0x0E, 0xA0,
		 0x7E, 0x94, 0x1B, 0x7B, 0xE9, 0x13, 0x48, 0xF9,
		 0xFC, 0xB1, 0x70, 0xE2, 0x21, 0x7F, 0xEC, 0xD9,
		 0x7F, 0x9F, 0x68, 0xAD, 0xB1, 0x6E, 0x5D, 0x7D,
		 0x21, 0xE5, 0x69, 0xD2, 0x80, 0xED, 0x77, 0x5C},
		{0xBB, 0xAF, 0x2F, 0xC3}
	},
        /*Custom test 4*/
        {
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		0x01234567,
		0xA,
		0x0,
		64,
		{0x5B, 0xAD, 0x72, 0x47, 0x10, 0xBA, 0x1C, 0x56},
		{0x1B, 0x3D, 0x0f, 0x74}
	},
        /*Custom test 5*/
	{
		{0xC9, 0xE6, 0xCE, 0xC4, 0x60, 0x7C, 0x72, 0xDB,
		 0x00, 0x0A, 0xEF, 0xA8, 0x83, 0x85, 0xAB, 0x0A},
		0xA94059DA,
		0xA,
		0x1,
		480,
		{0x98, 0x3B, 0x41, 0xD4, 0x7D, 0x78, 0x0C, 0x9E,
		 0x1A, 0xD1, 0x1D, 0x7E, 0xB7, 0x03, 0x91, 0xB1,
                 0xDE, 0x0B, 0x35, 0xDA, 0x2D, 0xC6, 0x2F, 0x83,
		 0xE7, 0xB7, 0x8D, 0x63, 0x06, 0xCA, 0x0E, 0xA0,
		 0x7E, 0x94, 0x1B, 0x7B, 0xE9, 0x13, 0x48, 0xF9,
		 0xFC, 0xB1, 0x70, 0xE2, 0x21, 0x7F, 0xEC, 0xD9,
		 0x7F, 0x9F, 0x68, 0xAD, 0xB1, 0x6E, 0x5D, 0x7D,
		 0x21, 0xE5, 0x69, 0xD2, 0x80, 0xED, 0x77, 0x5C},
		{0x39, 0x5C, 0x11, 0x92}
	},
};
#endif
