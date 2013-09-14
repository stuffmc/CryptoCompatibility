/*
     File: RSAOperationsTestsT.m
 Abstract: Unit tests for the RSA operations that use the SecTransform API.
  Version: 1.0
 
 Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple
 Inc. ("Apple") in consideration of your agreement to the following
 terms, and your use, installation, modification or redistribution of
 this Apple software constitutes acceptance of these terms.  If you do
 not agree with these terms, please do not use, install, modify or
 redistribute this Apple software.
 
 In consideration of your agreement to abide by the following terms, and
 subject to these terms, Apple grants you a personal, non-exclusive
 license, under Apple's copyrights in this original Apple software (the
 "Apple Software"), to use, reproduce, modify and redistribute the Apple
 Software, with or without modifications, in source and/or binary forms;
 provided that if you redistribute the Apple Software in its entirety and
 without modifications, you must retain this notice and the following
 text and disclaimers in all such redistributions of the Apple Software.
 Neither the name, trademarks, service marks or logos of Apple Inc. may
 be used to endorse or promote products derived from the Apple Software
 without specific prior written permission from Apple.  Except as
 expressly stated in this notice, no other rights or licenses, express or
 implied, are granted by Apple herein, including but not limited to any
 patent rights that may be infringed by your derivative works or by other
 works in which the Apple Software may be incorporated.
 
 The Apple Software is provided by Apple on an "AS IS" basis.  APPLE
 MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND
 OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS.
 
 IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL
 OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION,
 MODIFICATION AND/OR DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED
 AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING NEGLIGENCE),
 STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
 
 Copyright (C) 2013 Apple Inc. All Rights Reserved.
 
 */

#import "RSAOperationsTestsT.h"

#import "QCCRSASHA1SignT.h"
#import "QCCRSASHA1VerifyT.h"
#import "QCCRSASmallCryptorT.h"

#import "ToolCommon.h"
#import "QHex.h"

#include <sys/utsname.h>

@interface RSAOperationsTestsT ()

@property (nonatomic, assign, readonly ) SecKeyRef  publicKey;
@property (nonatomic, assign, readonly ) SecKeyRef  privateKey;
@property (nonatomic, assign, readwrite) BOOL       rsaWithoutPaddingImplemented;

@end

@implementation RSAOperationsTestsT : SenTestCase

- (void)setUp
{
    OSStatus        err;
    CFTypeRef       matchResult;

    [super setUp];

    [ToolCommon sharedInstance].debugRunOpOnMainThread = YES;

    assert(self->_publicKey == NULL);
    assert(self->_privateKey == NULL);

    // public key
    
    err = SecItemCopyMatching((__bridge CFDictionaryRef) @{
            (__bridge id) kSecClass:        (__bridge id) kSecClassKey,
            (__bridge id) kSecReturnRef:    (__bridge id) kCFBooleanTrue, 
            (__bridge id) kSecAttrKeyClass: (__bridge id) kSecAttrKeyClassPublic, 
            (__bridge id) kSecAttrKeyType:  (__bridge id) kSecAttrKeyTypeRSA,
            (__bridge id) kSecAttrLabel:                  @"Imported Public Key"
        }, 
        &matchResult
    );
    assert(err == errSecSuccess);
    assert(CFGetTypeID(matchResult) == SecKeyGetTypeID());
    self->_publicKey = (SecKeyRef) matchResult;
    CFRetain(self->_publicKey);
    CFRelease(matchResult);
    
    // private key
    
    err = SecItemCopyMatching((__bridge CFDictionaryRef) @{
            (__bridge id) kSecClass:        (__bridge id) kSecClassKey,
            (__bridge id) kSecReturnRef:    (__bridge id) kCFBooleanTrue, 
            (__bridge id) kSecAttrKeyClass: (__bridge id) kSecAttrKeyClassPrivate, 
            (__bridge id) kSecAttrKeyType:  (__bridge id) kSecAttrKeyTypeRSA,
            (__bridge id) kSecAttrLabel:                  @"Imported Private Key"
        }, 
        &matchResult
    );
    assert(err == errSecSuccess);
    assert(CFGetTypeID(matchResult) == SecKeyGetTypeID());
    self->_privateKey = (SecKeyRef) matchResult;
    CFRetain(self->_privateKey);
    CFRelease(matchResult);
    
    // Prior to OS X 10.8, the security transform used by QCCRSASmallCryptorT does not implement
    // the 'no padding' option (kSecPaddingNoneKey) <rdar://problem/9987765>.  If we're running on
    // such a system we just skip the tests that rely on this; otherwise the test log fills up
    // with reports of problems that we know about and can't find.
    //
    // Note that 12 is the Darwin major version for 10.8.
    
    self.rsaWithoutPaddingImplemented = YES;
    {
        int                 i;
        struct utsname      unameInfo;
        
        i = uname(&unameInfo);
        if (i >= 0) {
            i = atoi(unameInfo.release);
            if ( (i > 0) && (i < 12) ) {
                self.rsaWithoutPaddingImplemented = NO;
            }
        }
    }
}

- (void)tearDown
{
    if (self->_publicKey != NULL) {
        CFRelease(self->_publicKey);
        self->_publicKey = NULL;
    }
    if (self->_privateKey != NULL) {
        CFRelease(self->_privateKey);
        self->_privateKey = NULL;
    }
    [super tearDown];
}

- (BOOL)verifyFile:(NSString *)fileName
{
    NSData *            fileData;
    NSData *            signatureData;
    QCCRSASHA1VerifyT * op;
    
    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:fileName withExtension:@"cer"]];
    assert(fileData != nil);
    
    signatureData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test.cer" withExtension:@"sig"]];
    assert(signatureData != nil);
    
    op = [[QCCRSASHA1VerifyT alloc] initWithInputData:fileData publicKey:self.publicKey signatureData:signatureData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    assert(op.error == nil);
    return op.verified;
}

- (void)testRSASHA1Verify
{
    STAssertTrue([self verifyFile:@"test"], @"");
    STAssertFalse([self verifyFile:@"test-corrupted"], @"");
}

- (void)testRSASHA1Sign
{
    NSData *            fileData;
    QCCRSASHA1SignT *   op;
    NSData *            expectedSignatureData;
    
    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(fileData != nil);
    
    expectedSignatureData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test.cer" withExtension:@"sig"]];
    assert(expectedSignatureData != nil);
    
    op = [[QCCRSASHA1SignT alloc] initWithInputData:fileData privateKey:self.privateKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(op.signatureData, expectedSignatureData, @"");
}

- (void)testRSASmallCryptor
{
    NSData *                fileData;
    QCCRSASmallCryptorT *   op;
    
    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-32" withExtension:@"dat"]];
    assert(fileData != nil);
    
    op = [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:fileData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    
    if (op.smallOutputData != nil) {
        op = [[QCCRSASmallCryptorT alloc] initToDecryptSmallInputData:op.smallOutputData key:self.privateKey];
        [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
        STAssertNil(op.error, @"");

        STAssertEqualObjects(fileData, op.smallOutputData, @"");
    }
}

// We can't test a fixed encryption in the padding case because the padding adds some 
// randomness so that no two encryptions are the same.

- (void)testRSADecrypt
{
    NSData *                fileData;
    QCCRSASmallCryptorT *   op;
    NSData *                cyphertext32Data;

    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-32" withExtension:@"dat"]];
    assert(fileData != nil);
    
    // This is the "plaintext-32.dat" data encrypted with the public key using the 
    // following OpenSSL command:
    //
    // $ openssl rsautl -encrypt -pkcs -pubin -inkey TestData/public.pem -in TestData/plaintext-32.dat

    cyphertext32Data = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-pkcs1-32" withExtension:@"dat"]];
    assert(cyphertext32Data != nil);
    
    op = [[QCCRSASmallCryptorT alloc] initToDecryptSmallInputData:cyphertext32Data key:self.privateKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");

    STAssertEqualObjects(fileData, op.smallOutputData, @"");
}

- (void)testRSAEncryptNoPad
{
    NSData *                fileData;
    QCCRSASmallCryptorT *   op;
    NSData *                cyphertext256Data;

    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-256" withExtension:@"dat"]];
    assert(fileData != nil);
    
    // This is the "plaintext-256.dat" data encrypted with the public key using the 
    // following OpenSSL command:
    //
    // $ openssl rsautl -encrypt -raw -pubin -inkey TestData/public.pem -in TestData/plaintext-256.dat
    
    cyphertext256Data = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-nopad-256" withExtension:@"dat"]];
    assert(cyphertext256Data != nil);
    
    op = [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:fileData key:self.publicKey];
    op.padding = kQCCRSASmallCryptorTPaddingNone;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    if (self.rsaWithoutPaddingImplemented) {
        STAssertNil(op.error, @"");
        STAssertEqualObjects(op.smallOutputData, cyphertext256Data, @"");
    } else {
        STAssertNotNil(op.error, @"");
        STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
        STAssertEquals([op.error code], (NSInteger) CSSMERR_CSP_INVALID_ATTR_PADDING, @"");
        STAssertNil(op.smallOutputData, @"");
    }
}

- (void)testRSADecryptNoPad
{
    NSData *                fileData;
    QCCRSASmallCryptorT *   op;
    NSData *                cyphertext256Data;

    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-256" withExtension:@"dat"]];
    assert(fileData != nil);
    
    // This is the "plaintext-256.dat" data encrypted with the public key using the 
    // following OpenSSL command:
    //
    // $ openssl rsautl -encrypt -raw -pubin -inkey TestData/public.pem -in TestData/plaintext-256.dat
    
    cyphertext256Data = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-nopad-256" withExtension:@"dat"]];
    assert(cyphertext256Data != nil);

    op = [[QCCRSASmallCryptorT alloc] initToDecryptSmallInputData:cyphertext256Data key:self.privateKey];
    op.padding = kQCCRSASmallCryptorTPaddingNone;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    if (self.rsaWithoutPaddingImplemented) {
        STAssertNil(op.error, @"");
        STAssertEqualObjects(fileData, op.smallOutputData, @"");
    } else {
        STAssertNotNil(op.error, @"");
        STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
        STAssertEquals([op.error code], (NSInteger) CSSMERR_CSP_INVALID_ATTR_PADDING, @"");
        STAssertNil(op.smallOutputData, @"");
    }
}

- (void)testRSAVerifyError
{
    NSData *                fileData;
    NSData *                signatureData;
    QCCRSASHA1VerifyT *     op;
    
    // passing private key to verify
    
    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(fileData != nil);
    
    signatureData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test.cer" withExtension:@"sig"]];
    assert(signatureData != nil);
    
    op = [[QCCRSASHA1VerifyT alloc] initWithInputData:fileData publicKey:self.privateKey signatureData:signatureData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], @"Internal CSSM error", @"");
    STAssertEquals([op.error code], (NSInteger) CSSMERR_CSP_INVALID_KEY_CLASS, @"");
    STAssertFalse(op.verified, @"");        // this would be true if we'd passed in self.publicKey
    
    // passing public key to sign
}

- (void)testRSASignError
{
    NSData *                fileData;
    NSData *                expectedSignatureData;
    QCCRSASHA1SignT *       op;
    
    // Note: This test fails on OS X 10.7.x because the signing transform doesn't fail if
    // you pass it a public key; rather it succeeds, but produces gibberish results.
    
    // passing public key to sign
    
    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(fileData != nil);
    
    expectedSignatureData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test.cer" withExtension:@"sig"]];
    assert(expectedSignatureData != nil);
    
    op = [[QCCRSASHA1SignT alloc] initWithInputData:fileData privateKey:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], @"Internal CSSM error", @"");
    STAssertEquals([op.error code], (NSInteger) CSSMERR_CSP_INVALID_KEY_CLASS, @"");
    STAssertNil(op.signatureData, @"");
}

- (void)testRSACryptorError
{
    NSData *                plaintextData;
    NSData *                cyphertextData;
    QCCRSASmallCryptorT *   op;
    
    // encrypt with the private key
    
    plaintextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-32" withExtension:@"dat"]];
    assert(plaintextData != nil);
    
    op = [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:plaintextData key:self.privateKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) CSSMERR_CSP_INVALID_KEY_CLASS, @"");
    STAssertNil(op.smallOutputData, @"");

    // decrypt with the public key
    
    cyphertextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-pkcs1-32" withExtension:@"dat"]];
    assert(cyphertextData != nil);
    
    op = [[QCCRSASmallCryptorT alloc] initToDecryptSmallInputData:cyphertextData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) CSSMERR_CSP_INVALID_KEY_CLASS, @"");
    STAssertNil(op.smallOutputData, @"");

    // padded encrypt too big
    
    plaintextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-332" withExtension:@"dat"]];
    assert(plaintextData != nil);
    
    op = [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
    STAssertNil(op.smallOutputData, @"");
    
    plaintextData = [plaintextData subdataWithRange:NSMakeRange(0, 256)];

    op = [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
    STAssertNil(op.smallOutputData, @"");

    plaintextData = [plaintextData subdataWithRange:NSMakeRange(0, 246)];

    op = [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
    STAssertNil(op.smallOutputData, @"");

    plaintextData = [plaintextData subdataWithRange:NSMakeRange(0, 245)];

    op = [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");

    // raw encrypt wrong length

    plaintextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-256" withExtension:@"dat"]];
    assert(plaintextData != nil);
    
    op = [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    op.padding = kQCCRSASmallCryptorTPaddingNone;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    if (self.rsaWithoutPaddingImplemented) {
        STAssertNil(op.error, @"");
    } else {
        STAssertNotNil(op.error, @"");
        STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
        STAssertEquals([op.error code], (NSInteger) CSSMERR_CSP_INVALID_ATTR_PADDING, @"");
        STAssertNil(op.smallOutputData, @"");
    }
    
    plaintextData = [plaintextData subdataWithRange:NSMakeRange(0, 255)];

    op = [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    op.padding = kQCCRSASmallCryptorTPaddingNone;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    if (self.rsaWithoutPaddingImplemented) {
        STAssertNotNil(op.error, @"");
        STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
        STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
        STAssertNil(op.smallOutputData, @"");
    } else {
        STAssertNotNil(op.error, @"");
        STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
        STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
        STAssertNil(op.smallOutputData, @"");
    }
    
    // padded decrypt wrong length

    cyphertextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-pkcs1-32" withExtension:@"dat"]];
    assert(cyphertextData != nil);
    
    cyphertextData = [cyphertextData subdataWithRange:NSMakeRange(0, 255)];
    
    op = [[QCCRSASmallCryptorT alloc] initToDecryptSmallInputData:cyphertextData key:self.privateKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
    STAssertNil(op.smallOutputData, @"");
    
    // raw decrypt wrong length
    
    cyphertextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-nopad-256" withExtension:@"dat"]];
    assert(cyphertextData != nil);

    cyphertextData = [cyphertextData subdataWithRange:NSMakeRange(0, 255)];
    
    op = [[QCCRSASmallCryptorT alloc] initToDecryptSmallInputData:cyphertextData key:self.privateKey];
    op.padding = kQCCRSASmallCryptorTPaddingNone;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    if (self.rsaWithoutPaddingImplemented) {
        STAssertNotNil(op.error, @"");
        STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
        STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
        STAssertNil(op.smallOutputData, @"");
    } else {
        STAssertNotNil(op.error, @"");
        STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
        STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
        STAssertNil(op.smallOutputData, @"");
    }
}

- (void)testRSAThrows
{
    STAssertThrows((void) [[QCCRSASHA1VerifyT alloc] initWithInputData:nil publicKey:self.publicKey signatureData:[NSData data]], @"");
    STAssertThrows((void) [[QCCRSASHA1VerifyT alloc] initWithInputData:[NSData data] publicKey:NULL signatureData:[NSData data]], @"");
    STAssertThrows((void) [[QCCRSASHA1VerifyT alloc] initWithInputData:[NSData data] publicKey:self.publicKey signatureData:nil], @"");

    STAssertThrows((void) [[QCCRSASHA1SignT alloc] initWithInputData:nil privateKey:self.privateKey], @"");
    STAssertThrows((void) [[QCCRSASHA1SignT alloc] initWithInputData:[NSData data] privateKey:NULL], @"");

    STAssertThrows((void) [[QCCRSASmallCryptorT alloc] initToDecryptSmallInputData:nil key:self.publicKey], @"");
    STAssertThrows((void) [[QCCRSASmallCryptorT alloc] initToDecryptSmallInputData:[NSData data] key:NULL], @"");
    STAssertThrows((void) [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:nil key:self.privateKey], @"");
    STAssertThrows((void) [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:[NSData data] key:NULL], @"");
}

@end
