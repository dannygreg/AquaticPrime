//
// AquaticPrime.h
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

#import "AquaticPrime+SerialNumberSupport.h"

#import "AquaticPrime+Private.h"
#import "AquaticPrimeSigning.h"

#import <openssl/ssl.h>
#import <openssl/hmac.h>

@implementation AquaticPrime (SerialNumberSupport)

- (NSString *)serialNumberForDictionary:(NSDictionary *)dict error:(NSError **)err
{
	NSData *signatureData = AQPSignatureForDictionaryWithKey(dict, self.rsaKey, err);
	if (signatureData == nil)
		return nil;
	
	BIO *mem = BIO_new(BIO_s_mem());
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); 
	mem = BIO_push(b64, mem);
	
	CFRetain(self); // Note: begin interior pointer access
	BIO_write(mem, [signatureData bytes], [signatureData length]);
	CFRelease(self); // Note: end interior pointer access
	
    (void)BIO_flush(mem);
	
	char *base64Pointer;
    long base64Length = BIO_get_mem_data(mem, &base64Pointer);
	
	NSString *base64String = [[[NSString alloc] initWithBytes:base64Pointer length:base64Length encoding:NSUTF8StringEncoding] autorelease];
	
	BIO_free_all(mem);
	
	return base64String;
}

- (BOOL)verifySerial:(NSString *)serial forDictionary:(NSDictionary *)dict error:(NSError **)err
{
	NSData *initialSerialData = [serial dataUsingEncoding:NSUTF8StringEncoding];
    BIO *command = BIO_new(BIO_f_base64());
    BIO *context = BIO_new_mem_buf((void *)[initialSerialData bytes], [initialSerialData length]);
	
    // Tell the context to encode base64
    context = BIO_push(command, context);
	
    // Encode all the data
    NSMutableData *serialData = [NSMutableData data];
    
#define BUFFSIZE 256
    int len = 0;
    char inbuf[BUFFSIZE];
    while ((len = BIO_read(context, inbuf, BUFFSIZE)) > 0)
        [serialData appendBytes:inbuf length:len];
	
    BIO_free_all(context);
	
	return [self verifySignature:serialData forDictionary:dict error:err];
}

@end
