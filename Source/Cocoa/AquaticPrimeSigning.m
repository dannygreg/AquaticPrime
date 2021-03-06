//
// AquaticPrime.m
// AquaticPrime Framework
//
// Copyright (c) 2005-2009 Lucas Newman and other contributors
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//	•Redistributions of source code must retain the above copyright notice,
//	 this list of conditions and the following disclaimer.
//	•Redistributions in binary form must reproduce the above copyright notice,
//	 this list of conditions and the following disclaimer in the documentation and/or
//	 other materials provided with the distribution.
//	•Neither the name of Aquatic nor the names of its contributors may be used to 
//	 endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
// IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
// OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//***************************************************************************

#import "AquaticPrimeSigning.h"

#import "AquaticPrimeError.h"

#include <openssl/sha.h>
#include <openssl/err.h>

NSData *AQPSignatureForDictionaryWithKey(NSDictionary *dict, RSA *key, NSError **err)
{
	// Grab all values from the dictionary
	NSMutableArray *keyArray = [NSMutableArray arrayWithArray:[dict allKeys]];
	NSMutableData *dictData = [NSMutableData data];
	
	// Sort the keys so we always have a uniform order
	[keyArray sortUsingSelector:@selector(caseInsensitiveCompare:)];
	
	int i;
	for (i = 0; i < [keyArray count]; i++)
	{
		id curValue = [dict objectForKey:[keyArray objectAtIndex:i]];
		char *desc = (char *)[[curValue description] UTF8String];
		// We use strlen instead of [string length] so we can get all the bytes of accented characters
		[dictData appendBytes:desc length:strlen(desc)];
	}
	
	// Hash the data
	unsigned char digest[20];
	SHA1([dictData bytes], [dictData length], digest);
	
	int rsaLength = RSA_size(key);
	unsigned char *signature = (unsigned char*)malloc(rsaLength);
	int bytes = RSA_private_encrypt(20, digest, signature, key, RSA_PKCS1_PADDING);
	
	if (bytes == -1) {
		if (err != NULL)
			*err = AQPErrorForERRError(ERR_get_error());
		return nil;
	}
	
	return [NSData dataWithBytes:signature length:bytes];
}
