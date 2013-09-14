/*
     File: CryptorOperationsTests.m
 Abstract: Unit tests for the cryptor operations.
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

#import "CryptorOperationsTests.h"

#import "QCCAESCryptor.h"
#import "QCCAESPadCryptor.h"
#import "QCCAESPadBigCryptor.h"

#import "ToolCommon.h"

#import "QHex.h"

#import <CommonCrypto/CommonCrypto.h>

@implementation CryptorOperationsTests

- (void)setUp
{
    [super setUp];
    [ToolCommon sharedInstance].debugRunOpOnMainThread = YES;
}

// AES-128 ECB

- (void)testAES128ECBEncryption
{
    NSData *            inputData;
    NSData *            keyData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-336" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-ecb-336" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    op = [[QCCAESCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    op.ivData = nil;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES128ECBEncryptionEmpty
{
    NSData *            inputData;
    NSData *            keyData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData data];
    assert(inputData != nil);
    
    expectedOutputData = [NSData data];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    op = [[QCCAESCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    op.ivData = nil;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES128ECBDecryption
{
    NSData *            inputData;
    NSData *            keyData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-ecb-336" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-336" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    op = [[QCCAESCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    op.ivData = nil;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES128ECBDecryptionEmpty
{
    NSData *            inputData;
    NSData *            keyData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData data];
    assert(inputData != nil);
    
    expectedOutputData = [NSData data];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    op = [[QCCAESCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    op.ivData = nil;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

// AES-128 CBC

- (void)testAES128CBCEncryption
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-336" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-336" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES128CBCEncryptionEmpty
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData data];
    assert(inputData != nil);
    
    expectedOutputData = [NSData data];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES128CBCDecryption
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-336" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-336" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES128CBCDecryptionEmpty
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData data];
    assert(inputData != nil);
    
    expectedOutputData = [NSData data];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

// AES-256 ECB

- (void)testAES256ECBEncryption
{
    NSData *            inputData;
    NSData *            keyData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-336" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-256-ecb-336" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a"];
    assert(keyData != nil);

    op = [[QCCAESCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    op.ivData = nil;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES256ECBDecryption
{
    NSData *            inputData;
    NSData *            keyData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-256-ecb-336" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-336" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a"];
    assert(keyData != nil);
    
    op = [[QCCAESCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    op.ivData = nil;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

// AES-256 CBC

- (void)testAES256CBCEncryption
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-336" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-256-cbc-336" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES256CBCDecryption
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESCryptor *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-256-cbc-336" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-336" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

// AES-128 Pad CBC

- (void)testAES128PadCBCEncryption
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESPadCryptor *  op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-332" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-332" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESPadCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES128PadCBCEncryptionEmpty
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESPadCryptor *  op;
    NSData *            expectedOutputData;
    
    inputData = [NSData data];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-0" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESPadCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES128PadCBCDecryption
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESPadCryptor *  op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-332" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-332" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESPadCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES128PadCBCDecryptionEmpty
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESPadCryptor *  op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-0" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData data];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESPadCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

// AES-128 Pad Big CBC

- (void)testAES128PadBigCBCEncryption
{
    NSData *                inputData;
    NSInputStream *         inputStream;
    NSOutputStream *        outputStream;
    NSData *                keyData;
    NSData *                ivData;
    QCCAESPadBigCryptor *   op;
    NSData *                expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-332" withExtension:@"dat"]];
    assert(inputData != nil);

    inputStream = [NSInputStream inputStreamWithData:inputData];
    assert(inputStream != nil);
    
    outputStream = [NSOutputStream outputStreamToMemory];
    assert(outputStream != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-332" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESPadBigCryptor alloc] initToEncryptInputStream:inputStream toOutputStream:outputStream keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, [outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey], @"");
}

- (void)testAES128PadBigCBCDecryption
{
    NSData *                inputData;
    NSInputStream *         inputStream;
    NSOutputStream *        outputStream;
    NSData *                keyData;
    NSData *                ivData;
    QCCAESPadBigCryptor *   op;
    NSData *                expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-332" withExtension:@"dat"]];
    assert(inputData != nil);
    
    inputStream = [NSInputStream inputStreamWithData:inputData];
    assert(inputStream != nil);
    
    outputStream = [NSOutputStream outputStreamToMemory];
    assert(outputStream != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-332" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESPadBigCryptor alloc] initToDecryptInputStream:inputStream toOutputStream:outputStream keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, [outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey], @"");
}

// AES-256 Pad CBC

- (void)testAES256PadCBCEncryption
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESPadCryptor *  op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-332" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-256-cbc-332" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESPadCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testAES256PadCBCDecryption
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESPadCryptor *  op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-256-cbc-332" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-332" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESPadCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

// errors

- (void)testAESCryptorErrors
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESCryptor *     op;
    
    // data not a multiple of the block size
    
    inputData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e"];
    assert(inputData != nil);

    keyData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e0f"];
    assert(keyData != nil);

    op = [[QCCAESCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.outputData, @"");

    op = [[QCCAESCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.outputData, @"");

    // key not one of the standard AES key lengths
    
    inputData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e0f"];
    assert(inputData != nil);

    keyData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e"];
    assert(keyData != nil);

    op = [[QCCAESCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.outputData, @"");

    op = [[QCCAESCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.outputData, @"");

    // IV specified, but not a multiple of the block size
    
    inputData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e0f"];
    assert(inputData != nil);

    keyData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e0f"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e"];
    assert(keyData != nil);

    op = [[QCCAESCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.outputData, @"");

    op = [[QCCAESCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.outputData, @"");
}

- (void)testAESPadCryptorErrors
{
    NSData *            inputData;
    NSData *            keyData;
    NSData *            ivData;
    QCCAESPadCryptor *  op;
    
    // data not a multiple of the block size
    
    // Note that we don't test the encrypt case here because the whole point of padding 
    // is to allow us to encrypt data that's not a multiple of the block length.
    
    inputData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e"];
    assert(inputData != nil);

    keyData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e0f"];
    assert(keyData != nil);

    op = [[QCCAESPadCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESPadCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.outputData, @"");

    // key not one of the standard AES key lengths
    
    inputData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e0f"];
    assert(inputData != nil);

    keyData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e"];
    assert(keyData != nil);

    op = [[QCCAESPadCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESPadCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.outputData, @"");

    op = [[QCCAESPadCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESPadCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.outputData, @"");

    // IV specified, but not a multiple of the block size
    
    inputData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e0f"];
    assert(inputData != nil);

    keyData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e0f"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"000102030405060708090a0b0c0d0e"];
    assert(keyData != nil);

    op = [[QCCAESPadCryptor alloc] initToEncryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESPadCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.outputData, @"");

    op = [[QCCAESPadCryptor alloc] initToDecryptInputData:inputData keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESPadCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.outputData, @"");
}

- (void)testAES128PadBigCryptorErrors
{
    NSData *                inputData;
    NSInputStream *         inputStream;
    NSOutputStream *        outputStream;
    NSData *                keyData;
    NSData *                ivData;
    QCCAESPadBigCryptor *   op;
    NSData *                expectedOutputData;
    NSData *                actualOutputData;
    
    // data not a multiple of the block size

    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-332" withExtension:@"dat"]];
    assert(inputData != nil);
    
    inputData = [inputData subdataWithRange:NSMakeRange(0, [inputData length] - 1)];
    assert(inputData != nil);
    
    inputStream = [NSInputStream inputStreamWithData:inputData];
    assert(inputStream != nil);
    
    outputStream = [NSOutputStream outputStreamToMemory];
    assert(outputStream != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-332" withExtension:@"dat"]];
    assert(expectedOutputData != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESPadBigCryptor alloc] initToDecryptInputStream:inputStream toOutputStream:outputStream keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESPadBigCryptorErrorDomain, @"");
    // The actual error we get is kCCBufferTooSmall, which doesn't make much sense in this 
    // context, but that's what Common Crypto gives us.  Rather than test for a specific 
    // error, we test for any error.
    STAssertTrue([op.error code] != kCCSuccess, @"");
    // We actually get partial output data.  Check that the any data we got is correct.
    actualOutputData = [outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
    STAssertNotNil(actualOutputData, @"");
    STAssertTrue([actualOutputData length] < [expectedOutputData length], @"");     // shouldn't have got all the bytes
    STAssertEqualObjects(actualOutputData, [expectedOutputData subdataWithRange:NSMakeRange(0, [actualOutputData length])], @"");

    // key not one of the standard AES key lengths

    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-332" withExtension:@"dat"]];
    assert(inputData != nil);
    
    inputStream = [NSInputStream inputStreamWithData:inputData];
    assert(inputStream != nil);
    
    outputStream = [NSOutputStream outputStreamToMemory];
    assert(outputStream != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF757"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFFB7"];
    assert(ivData != nil);
    
    op = [[QCCAESPadBigCryptor alloc] initToDecryptInputStream:inputStream toOutputStream:outputStream keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESPadBigCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertEquals([[outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey] length], (NSUInteger) 0, @"");

    // IV specified, but not a multiple of the block size

    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"cyphertext-aes-128-cbc-332" withExtension:@"dat"]];
    assert(inputData != nil);
    
    inputStream = [NSInputStream inputStreamWithData:inputData];
    assert(inputStream != nil);
    
    outputStream = [NSOutputStream outputStreamToMemory];
    assert(outputStream != nil);
    
    keyData = [QHex dataWithHexString:@"0C1032520302EC8537A4A82C4EF7579D"];
    assert(keyData != nil);

    ivData = [QHex dataWithHexString:@"AB5BBEB426015DA7EEDCEE8BEE3DFF"];
    assert(ivData != nil);
    
    op = [[QCCAESPadBigCryptor alloc] initToDecryptInputStream:inputStream toOutputStream:outputStream keyData:keyData];
    op.ivData = ivData;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCAESPadBigCryptorErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertEquals([[outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey] length], (NSUInteger) 0, @"");
}

- (void)testCryptoThrows
{
    STAssertThrows((void) [[QCCAESCryptor alloc] initToDecryptInputData:nil keyData:[NSData data]], @"");
    STAssertThrows((void) [[QCCAESCryptor alloc] initToDecryptInputData:[NSData data] keyData:nil], @"");
    STAssertThrows((void) [[QCCAESCryptor alloc] initToEncryptInputData:nil keyData:[NSData data]], @"");
    STAssertThrows((void) [[QCCAESCryptor alloc] initToEncryptInputData:[NSData data] keyData:nil], @"");

    STAssertThrows((void) [[QCCAESPadCryptor alloc] initToDecryptInputData:nil keyData:[NSData data]], @"");
    STAssertThrows((void) [[QCCAESPadCryptor alloc] initToDecryptInputData:[NSData data] keyData:nil], @"");
    STAssertThrows((void) [[QCCAESPadCryptor alloc] initToEncryptInputData:nil keyData:[NSData data]], @"");
    STAssertThrows((void) [[QCCAESPadCryptor alloc] initToEncryptInputData:[NSData data] keyData:nil], @"");

    STAssertThrows((void) [[QCCAESPadBigCryptor alloc] initToDecryptInputStream:nil toOutputStream:[NSOutputStream outputStreamToMemory] keyData:[NSData data]], @"");
    STAssertThrows((void) [[QCCAESPadBigCryptor alloc] initToDecryptInputStream:[NSInputStream inputStreamWithData:[NSData data]] toOutputStream:nil keyData:[NSData data]], @"");
    STAssertThrows((void) [[QCCAESPadBigCryptor alloc] initToDecryptInputStream:[NSInputStream inputStreamWithData:[NSData data]] toOutputStream:[NSOutputStream outputStreamToMemory] keyData:nil], @"");
}

@end
