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

#import "LicenseTests.h"

#import "AquaticPrime.h"

@interface LicenseTests ()

@property (nonatomic, retain) AquaticPrime *validator;

- (NSURL *)testFileLocation;

@end

@implementation LicenseTests

@synthesize validator = _validator;

- (void)setUp
{
	self.validator = [[AquaticPrime alloc] init];
	NSError *err = nil;
	BOOL result = [self.validator setKey:@"0xD8921C4BE8E9004BE1BDB34DA95CCDE1EF710AF3F81FF4CB622BC219AD2215424DA55DB3EB4F3DEED9AED0A4BC8F7F288CC91BC3656F33AD2EEC9E19A7DD7068C1BDCC8ED892D9C823A1CBA79ED4B39427B8295139321F4F5C476E7DC413B9248A1A7AFA07F6FD5CE64A04039D855AF20C4B50FD13B9F18F0BE760E52B17F7A1" withPrivateKey:nil error:&err];
	STAssertTrue(result, @"Could not set public key on validator: %@", err);
}

- (void)tearDown
{
	[_validator release], _validator = nil;
	[super tearDown];
}

- (void)testLicenseFileRead
{
	NSData *licenseFileData = [NSData dataWithContentsOfURL:[self testFileLocation]];
	STAssertNotNil(licenseFileData, @"Could not read license file.");
	
	NSError *err = nil;
	NSDictionary *licenseDictionary = [self.validator verifiedDictionaryForLicenseFileData:licenseFileData error:&err];
	STAssertNotNil(licenseDictionary, @"Failed to verify a valid license file, giving error: %@", err);
}

- (void)testSerialNumberValidation
{
	NSMutableDictionary *testDictionary = [NSDictionary dictionaryWithContentsOfURL:[self testFileLocation]];
	STAssertNotNil(testDictionary, @"Failed to construct dictionary from test license file.");
	
	[testDictionary removeObjectForKey:@"Signature"];
	
	NSString *serial = @"b9e14e4b 5349fbeb b2ca7753 49d12a1a f31bb531 f5453e9a 42f43ea0 35322908 b68db8c6 c161256b 7c2ed853 c77aa0d8 37a7705d 33757b24 4bde6592 488db978 ead5765c fd3066f2 afcb5902 baa5252f 282aec23 54d06b57 ea57bb4f 28a26bf1 ebb3da9e 9fd23c51 ade7150d 78836b92 8462364d 339177fe b3b47df5 1b42c33a"
	NSError *err = nil;
	STAssertTrue([self.validator verifySerial:serial forDictionary:testDictionary error:err], @"Failed to verify serial number, giving error: %@", err);
}

#pragma mark -

- (NSURL *)testFileLocation
{
	NSURL *testFileLocation = [[NSBundle bundleForClass:[self class]] URLForResource:@"Test_License" withExtension:@"plist"];
	STAssertNotNil(testFileLocation, @"Could not determine location of the test license file.");
	
	return testFileLocation;
}

@end
