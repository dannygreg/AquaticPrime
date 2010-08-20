//
// AquaticPrime.m
// AquaticPrime Framework
//
// Copyright (c) 2005-2009 Lucas Newman and other contributors
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//	¥Redistributions of source code must retain the above copyright notice,
//	 this list of conditions and the following disclaimer.
//	¥Redistributions in binary form must reproduce the above copyright notice,
//	 this list of conditions and the following disclaimer in the documentation and/or
//	 other materials provided with the distribution.
//	¥Neither the name of Aquatic nor the names of its contributors may be used to 
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

#import "AquaticPrime.h"
#import "AquaticPrimeError.h"

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>

//***************************************************************************

//We use localisable strings if in a framework, if we have been compiled as a static lib we fall back to whatever was passed in

#ifdef AQUATICPRIME_BUILDING_FRAMEWORK 

#define AQPLocalisedString(string) NSLocalizedStringFromTableInBundle(string, nil, [NSBundle bundleForClass:[self class]], nil)

#else

#define AQPLocalisedString(string) string

#endif

#define AQPErrorForDescriptionWithCode(description, errorCode) [NSError errorWithDomain:AQPErrorDomain code:errorCode userInfo:[NSDictionary dictionaryWithObject:AQPLocalisedString(description) forKey:NSLocalizedDescriptionKey]]

//***************************************************************************

@interface AquaticPrime ()

@property (nonatomic, assign) RSA *rsaKey;

@end

//***************************************************************************

@implementation AquaticPrime

@synthesize hash = _hash;
@synthesize blacklist = _blacklist;

@synthesize rsaKey = _rsaKey;

- (id)init
{	
	ERR_load_crypto_strings();
	
	if (![super init])
		return nil;
	
	_rsaKey = nil;
	
	return self;
}

- (void)finalize
{	
	ERR_free_strings();
	
	if (self.rsaKey != nil)
		RSA_free(self.rsaKey);
	
	[super finalize];
}

- (BOOL)setKey:(NSString *)key withPrivateKey:(NSString *)privateKey error:(NSError **)err
{
	NSAssert(key != nil, @"Attempted to initialise AquaticPrime without a public key.");
	NSAssert(![key isEqualToString:@""], @"Attempted to initialise AquaticPrime with an empty public key.");
	
	if (self.rsaKey != nil)
		RSA_free(self.rsaKey);
		
	self.rsaKey = RSA_new();
	
	// We are using the constant public exponent e = 3
	BN_dec2bn(&self.rsaKey->e, "3");
	
	// Determine if we have hex or decimal values
	int result;
	if ([[key lowercaseString] hasPrefix:@"0x"])
		result = BN_hex2bn(&self.rsaKey->n, (const char *)[[key substringFromIndex:2] UTF8String]);
	else
		result = BN_dec2bn(&self.rsaKey->n, (const char *)[key UTF8String]);
		
	if (!result) {
		if (err != NULL) 
			*err = AQPErrorForERRError(ERR_get_error());
		
		return NO;
	}
	
	// Do the private portion if it exists
	if (privateKey && ![privateKey isEqualToString:@""]) {
		if ([[privateKey lowercaseString] hasPrefix:@"0x"])
			result = BN_hex2bn(&self.rsaKey->d, (const char *)[[privateKey substringFromIndex:2] UTF8String]);
		else
			result = BN_dec2bn(&self.rsaKey->d, (const char *)[privateKey UTF8String]);
			
		if (!result) {
			if (err != NULL)
				*err = AQPErrorForERRError(ERR_get_error());
			
			return NO;
		}
	}
	
	return YES;
}

- (NSString *)key
{
	if (!self.rsaKey || !self.rsaKey->n)
		return nil;
	
	char *cString = BN_bn2hex(self.rsaKey->n);
	
	NSString *nString = [[NSString alloc] initWithUTF8String:cString];
	OPENSSL_free(cString);
	
	return nString;
}

- (NSString *)privateKey
{	
	if (!self.rsaKey || !self.rsaKey->d)
		return nil;
	
	char *cString = BN_bn2hex(self.rsaKey->d);
	
	NSString *dString = [[NSString alloc] initWithUTF8String:cString];
	OPENSSL_free(cString);
	
	return dString;
}

#pragma mark Signing

- (NSData *)licenseDataForDictionary:(NSDictionary*)dict error:(NSError **)err
{	
	// Make sure we have a good key
	NSAssert(self.rsaKey != nil, @"Attempted to retrieve license data without first setting a key.");
	
	//TODO: Localise this error
	if (!self.rsaKey->n || !self.rsaKey->d) {
		if (err != NULL)
			*err = [NSError errorWithDomain:AQPErrorDomain code:-1 userInfo:[NSDictionary dictionaryWithObject:AQPLocalisedString(@"Invalid key.") forKey:NSLocalizedDescriptionKey]];
		
		return nil;
	}
	
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
	
	// Create the signature from 20 byte hash
	int rsaLength = RSA_size(self.rsaKey);
	unsigned char *signature = (unsigned char*)malloc(rsaLength);
	int bytes = RSA_private_encrypt(20, digest, signature, self.rsaKey, RSA_PKCS1_PADDING);
	
	if (bytes == -1) {
		if (err != NULL)
			*err = AQPErrorForERRError(ERR_get_error());
		return nil;
	}
	
	// Create the license dictionary
	NSMutableDictionary *licenseDict = [NSMutableDictionary dictionaryWithDictionary:dict];
	[licenseDict setObject:[NSData dataWithBytes:signature length:bytes]  forKey:@"Signature"];
	
	// Create the data from the dictionary
	NSString *error = nil;
	NSData *licenseFile = [[NSPropertyListSerialization dataFromPropertyList:licenseDict 
														format:kCFPropertyListXMLFormat_v1_0 
														errorDescription:&error] retain];
	
	if (licenseFile == nil) {
		if (err != NULL) 
			*err = [NSError errorWithDomain:AQPErrorDomain code:-2 userInfo:[NSDictionary dictionaryWithObject:error forKey:NSLocalizedDescriptionKey]];
		
		
		return nil;
	}
	
	return licenseFile;
}

- (NSDictionary*)dictionaryForLicenseData:(NSData *)data error:(NSError **)err
{	
	NSAssert(self.rsaKey != nil, @"Tried to parse license data before setting a key.");
	NSAssert(self.rsaKey->n, @"Invalid key.");
	
	void (^assignError)(NSError *) = ^ (NSError *newError) {
		if (err != NULL)
			*err = newError;
	};
	
	// Create a dictionary from the data
	NSMutableDictionary *licenseDict = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListMutableContainersAndLeaves format:NULL error:err];
	if (![licenseDict isKindOfClass:[NSMutableDictionary class]] || err) 
		return nil;
		
	NSData *signature = [licenseDict objectForKey:@"Signature"];
	if (!signature) {
		assignError(AQPErrorForDescriptionWithCode(@"No signature in license file.", -3));
		return nil;
	}
		
	
	// Decrypt the signature - should get 20 bytes back
	unsigned char checkDigest[20];
	if (RSA_public_decrypt([signature length], [signature bytes], checkDigest, self.rsaKey, RSA_PKCS1_PADDING) != 20) {
		assignError(AQPErrorForDescriptionWithCode(@"Invalid license signature.", -4));
		return nil;
	}
	
	// Make sure the license hash isn't on the blacklist
	NSMutableString *hashCheck = [NSMutableString string];
	int hashIndex;
	for (hashIndex = 0; hashIndex < 20; hashIndex++)
		[hashCheck appendFormat:@"%02x", checkDigest[hashIndex]];
	
	// Store the license hash in case we need it later
	self.hash = hashCheck;
	
	if (self.blacklist && [self.blacklist containsObject:hashCheck]) {
		assignError(AQPErrorForDescriptionWithCode(@"This license has been blacklisted.", -5));
		return nil;
	}
	
	// Remove the signature element
	[licenseDict removeObjectForKey:@"Signature"];
	
	// Grab all values from the dictionary
	NSMutableArray *keyArray = [NSMutableArray arrayWithArray:[licenseDict allKeys]];
	NSMutableData *dictData = [NSMutableData data];
	
	// Sort the keys so we always have a uniform order
	[keyArray sortUsingSelector:@selector(caseInsensitiveCompare:)];
	
	int objectIndex;
	for (objectIndex = 0; objectIndex < [keyArray count]; objectIndex++)
	{
		id currentValue = [licenseDict objectForKey:[keyArray objectAtIndex:objectIndex]];
		char *description = (char *)[[currentValue description] UTF8String];
		// We use strlen instead of [string length] so we can get all the bytes of accented characters
		[dictData appendBytes:description length:strlen(description)];
	}
	
	// Hash the data
	unsigned char digest[20];
	SHA1([dictData bytes], [dictData length], digest);
	
	// Check if the signature is a match	
	int checkIndex;
	for (checkIndex = 0; checkIndex < 20; checkIndex++) {
		if (checkDigest[checkIndex] ^ digest[checkIndex]) {
			assignError(AQPErrorForDescriptionWithCode(@"Invalid license signature.", -5));
			return nil;
		}
	}
	
	return [NSDictionary dictionaryWithDictionary:licenseDict];
}

@end

#undef AQPLocalisedString
#undef AQPErrorForDescriptionWithCode
