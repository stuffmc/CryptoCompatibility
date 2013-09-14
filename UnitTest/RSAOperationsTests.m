/*
     File: RSAOperationsTests.m
 Abstract: Unit tests for the RSA operations.
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

#import "RSAOperationsTests.h"

#import "QCCRSASHA1Sign.h"
#import "QCCRSASHA1Verify.h"
#import "QCCRSASmallCryptor.h"

#import "ToolCommon.h"
#import "QHex.h"

#include <Security/SecureTransport.h>       // needed for errSSLCrypto on older SDKs

@interface RSAOperationsTests ()

@property (nonatomic, assign, readonly ) SecKeyRef  publicKey;
@property (nonatomic, assign, readonly ) SecKeyRef  privateKey;

@end

@implementation RSAOperationsTests

- (void)setUp
{
    OSStatus            err;
    NSData *            certData;
    SecCertificateRef   cert;
    SecPolicyRef        policy;
    SecTrustRef         trust;
    SecTrustResultType  trustResult;

    [super setUp];

    [ToolCommon sharedInstance].debugRunOpOnMainThread = YES;

    assert(self->_publicKey == NULL);
    assert(self->_privateKey == NULL);

    // public key
    
    certData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(certData != nil);

    cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef) certData);
    assert(cert != NULL);
    
    policy = SecPolicyCreateBasicX509();
    
    err = SecTrustCreateWithCertificates(cert, policy, &trust);
    assert(err == errSecSuccess);
    
    err = SecTrustEvaluate(trust, &trustResult);
    assert(err == errSecSuccess);
    
    self->_publicKey = SecTrustCopyPublicKey(trust);
    assert(self->_publicKey != NULL);
    
    CFRelease(policy);
    CFRelease(cert);
    
    // private key
    
    NSData *            pkcs12Data;
    CFArrayRef          imported;
    NSDictionary *      importedItem;
    SecIdentityRef      identity;
    
    pkcs12Data = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"private" withExtension:@"p12"]];
    assert(pkcs12Data != nil);
    
    err = SecPKCS12Import((__bridge CFDataRef) pkcs12Data, (__bridge CFDictionaryRef) @{
        (__bridge NSString *) kSecImportExportPassphrase: @"test"
    }, &imported);
    assert(err == errSecSuccess);
    assert(CFArrayGetCount(imported) == 1);
    importedItem = (__bridge NSDictionary *) CFArrayGetValueAtIndex(imported, 0);
    assert([importedItem isKindOfClass:[NSDictionary class]]);
    identity = (__bridge SecIdentityRef) importedItem[(__bridge NSString *) kSecImportItemIdentity];
    assert(identity != NULL);
    
    err = SecIdentityCopyPrivateKey(identity, &self->_privateKey);
    assert(err == errSecSuccess);
    assert(self->_privateKey != NULL);
    
    CFRelease(imported);
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
    QCCRSASHA1Verify *  op;
    
    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:fileName withExtension:@"cer"]];
    assert(fileData != nil);
    
    signatureData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test.cer" withExtension:@"sig"]];
    assert(signatureData != nil);
    
    op = [[QCCRSASHA1Verify alloc] initWithInputData:fileData publicKey:self.publicKey signatureData:signatureData];
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
    QCCRSASHA1Sign *    op;
    NSData *            expectedSignatureData;
    
    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(fileData != nil);
    
    expectedSignatureData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test.cer" withExtension:@"sig"]];
    assert(expectedSignatureData != nil);
    
    op = [[QCCRSASHA1Sign alloc] initWithInputData:fileData privateKey:self.privateKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(op.signatureData, expectedSignatureData, @"");
}

- (void)testRSASmallCryptor
{
    NSData *                fileData;
    QCCRSASmallCryptor *    op;
    
    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-32" withExtension:@"dat"]];
    assert(fileData != nil);
    
    op = [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:fileData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    
    op = [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:op.smallOutputData key:self.privateKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");

    STAssertEqualObjects(fileData, op.smallOutputData, @"");
}

// We can't test a fixed encryption in the padding case because the padding adds some 
// randomness so that no two encryptions are the same.

- (void)testRSADecrypt
{
    NSData *                fileData;
    QCCRSASmallCryptor *    op;
    NSData *                cyphertext32Data;

    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-32" withExtension:@"dat"]];
    assert(fileData != nil);
    
    // This is the "plaintext-32.dat" data encrypted with the public key using the 
    // following OpenSSL command:
    //
    // $ openssl rsautl -encrypt -pkcs -pubin -inkey TestData/public.pem -in TestData/plaintext-32.dat
    
    cyphertext32Data = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-pkcs1-32" withExtension:@"dat"]];
    assert(cyphertext32Data != nil);

    op = [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:cyphertext32Data key:self.privateKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");

    STAssertEqualObjects(fileData, op.smallOutputData, @"");
}

- (void)testRSAEncryptNoPad
{
    NSData *                fileData;
    QCCRSASmallCryptor *    op;
    NSData *                cyphertext256Data;

    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-256" withExtension:@"dat"]];
    assert(fileData != nil);
    
    // This is the "plaintext-256.dat" data encrypted with the public key using the 
    // following OpenSSL command:
    //
    // $ openssl rsautl -encrypt -raw -pubin -inkey TestData/public.pem -in TestData/plaintext-256.dat
    
    cyphertext256Data = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-nopad-256" withExtension:@"dat"]];
    assert(cyphertext256Data != nil);

    op = [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:fileData key:self.publicKey];
    op.padding = kQCCRSASmallCryptorPaddingNone;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");

    STAssertEqualObjects(op.smallOutputData, cyphertext256Data, @"");
}

- (void)testRSADecryptNoPad
{
    NSData *                fileData;
    QCCRSASmallCryptor *    op;
    NSData *                cyphertext256Data;

    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-256" withExtension:@"dat"]];
    assert(fileData != nil);
    
    // This is the "plaintext-256.dat" data encrypted with the public key using the 
    // following OpenSSL command:
    //
    // $ openssl rsautl -encrypt -raw -pubin -inkey TestData/public.pem -in TestData/plaintext-256.dat
    
    cyphertext256Data = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-nopad-256" withExtension:@"dat"]];
    assert(cyphertext256Data != nil);

    op = [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:cyphertext256Data key:self.privateKey];
    op.padding = kQCCRSASmallCryptorPaddingNone;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");

    STAssertEqualObjects(fileData, op.smallOutputData, @"");
}

- (void)testRSAVerifyError
{
    NSData *                fileData;
    NSData *                signatureData;
    QCCRSASHA1Verify *      op;
    
    // passing private key to verify
    
    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(fileData != nil);
    
    signatureData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test.cer" withExtension:@"sig"]];
    assert(signatureData != nil);
    
    op = [[QCCRSASHA1Verify alloc] initWithInputData:fileData publicKey:self.privateKey signatureData:signatureData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecUnimplemented, @"");
    STAssertFalse(op.verified, @"");        // this would be true if we'd passed in self.publicKey
}

- (void)testRSASignError
{
    NSData *                fileData;
    NSData *                expectedSignatureData;
    QCCRSASHA1Sign *        op;
    
    // passing public key to sign
    
    fileData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(fileData != nil);
    
    expectedSignatureData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test.cer" withExtension:@"sig"]];
    assert(expectedSignatureData != nil);
    
    op = [[QCCRSASHA1Sign alloc] initWithInputData:fileData privateKey:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecUnimplemented, @"");
    STAssertNil(op.signatureData, @"");
}

- (void)testRSACryptorError
{
    NSData *                plaintextData;
    NSData *                cyphertextData;
    QCCRSASmallCryptor *    op;
    
    // encrypt with the private key
    
    plaintextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-32" withExtension:@"dat"]];
    assert(plaintextData != nil);
    
    op = [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:plaintextData key:self.privateKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecUnimplemented, @"");
    STAssertNil(op.smallOutputData, @"");

    // decrypt with the public key
    
    cyphertextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-pkcs1-32" withExtension:@"dat"]];
    assert(cyphertextData != nil);
    
    op = [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:cyphertextData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSSLCrypto, @"");
    STAssertNil(op.smallOutputData, @"");

    // padded encrypt too big
    
    plaintextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-332" withExtension:@"dat"]];
    assert(plaintextData != nil);
    
    op = [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
    STAssertNil(op.smallOutputData, @"");
    
    plaintextData = [plaintextData subdataWithRange:NSMakeRange(0, 256)];

    op = [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
    STAssertNil(op.smallOutputData, @"");

    plaintextData = [plaintextData subdataWithRange:NSMakeRange(0, 246)];

    op = [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
    STAssertNil(op.smallOutputData, @"");

    // Note: The following test fails on iOS 5.x because of an off-by-one error in the data 
    // length check in the Security framework.  To make it work on 5.x you have to change 
    // 245 to 244.  245 is definitely the right number, so I've left the test as it should be 
    // and commented about the failure here.

    plaintextData = [plaintextData subdataWithRange:NSMakeRange(0, 245)];

    op = [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");

    // raw encrypt wrong length

    plaintextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-256" withExtension:@"dat"]];
    assert(plaintextData != nil);
    
    op = [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    op.padding = kQCCRSASmallCryptorPaddingNone;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");

    plaintextData = [plaintextData subdataWithRange:NSMakeRange(0, 255)];

    op = [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:plaintextData key:self.publicKey];
    op.padding = kQCCRSASmallCryptorPaddingNone;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
    STAssertNil(op.smallOutputData, @"");

    // padded decrypt wrong length

    cyphertextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-pkcs1-32" withExtension:@"dat"]];
    assert(cyphertextData != nil);
    
    cyphertextData = [cyphertextData subdataWithRange:NSMakeRange(0, 255)];
    
    op = [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:cyphertextData key:self.privateKey];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
    STAssertNil(op.smallOutputData, @"");
    
    // raw decrypt wrong length
    
    cyphertextData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-rsa-nopad-256" withExtension:@"dat"]];
    assert(cyphertextData != nil);

    cyphertextData = [cyphertextData subdataWithRange:NSMakeRange(0, 255)];
    
    op = [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:cyphertextData key:self.privateKey];
    op.padding = kQCCRSASmallCryptorPaddingNone;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], NSOSStatusErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) errSecParam, @"");
    STAssertNil(op.smallOutputData, @"");
}

- (void)testRSAThrows
{
    STAssertThrows((void) [[QCCRSASHA1Verify alloc] initWithInputData:nil publicKey:self.publicKey signatureData:[NSData data]], @"");
    STAssertThrows((void) [[QCCRSASHA1Verify alloc] initWithInputData:[NSData data] publicKey:NULL signatureData:[NSData data]], @"");
    STAssertThrows((void) [[QCCRSASHA1Verify alloc] initWithInputData:[NSData data] publicKey:self.publicKey signatureData:nil], @"");

    STAssertThrows((void) [[QCCRSASHA1Sign alloc] initWithInputData:nil privateKey:self.privateKey], @"");
    STAssertThrows((void) [[QCCRSASHA1Sign alloc] initWithInputData:[NSData data] privateKey:NULL], @"");

    STAssertThrows((void) [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:nil key:self.publicKey], @"");
    STAssertThrows((void) [[QCCRSASmallCryptor alloc] initToDecryptSmallInputData:[NSData data] key:NULL], @"");
    STAssertThrows((void) [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:nil key:self.privateKey], @"");
    STAssertThrows((void) [[QCCRSASmallCryptor alloc] initToEncryptSmallInputData:[NSData data] key:NULL], @"");
}

@end
