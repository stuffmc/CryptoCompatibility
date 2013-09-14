/*
     File: DigestOperationsTests.m
 Abstract: Tests for the Base64 operations.
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

#import "DigestOperationsTests.h"

#import "QCCMD5Digest.h"
#import "QCCSHA1Digest.h"
#import "QCCHMACSHA1Authentication.h"

#import "ToolCommon.h"

#import "QHex.h"

@implementation DigestOperationsTests

- (void)setUp
{
    [super setUp];
    [ToolCommon sharedInstance].debugRunOpOnMainThread = YES;
}

- (void)testMD5Digest
{
    NSData *            inputData;
    QCCMD5Digest *      op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(inputData != nil);
    
    expectedOutputData = [QHex dataWithHexString:@"cdd202dcf9deea872f7c64f6081e526c"];
    assert(expectedOutputData != nil);
    
    op = [[QCCMD5Digest alloc] initWithInputData:inputData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertEqualObjects(expectedOutputData, op.outputDigest, @"");
}

- (void)testMD5DigestEmpty
{
    NSData *            inputData;
    QCCMD5Digest *      op;
    NSData *            expectedOutputData;
    
    inputData = [NSData data];
    assert(inputData != nil);
    
    expectedOutputData = [QHex dataWithHexString:@"d41d8cd98f00b204e9800998ecf8427e"];
    assert(expectedOutputData != nil);
    
    op = [[QCCMD5Digest alloc] initWithInputData:inputData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertEqualObjects(expectedOutputData, op.outputDigest, @"");
}

- (void)testSHA1Digest
{
    NSData *            inputData;
    QCCSHA1Digest *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(inputData != nil);
    
    expectedOutputData = [QHex dataWithHexString:@"c1ddfe7dd14c9b8dee83b46b87a408970fd2a83f"];
    assert(expectedOutputData != nil);
    
    op = [[QCCSHA1Digest alloc] initWithInputData:inputData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertEqualObjects(expectedOutputData, op.outputDigest, @"");
}

- (void)testSHA1DigestEmpty
{
    NSData *            inputData;
    QCCSHA1Digest *     op;
    NSData *            expectedOutputData;
    
    inputData = [NSData data];
    assert(inputData != nil);
    
    expectedOutputData = [QHex dataWithHexString:@"da39a3ee5e6b4b0d3255bfef95601890afd80709"];
    assert(expectedOutputData != nil);
    
    op = [[QCCSHA1Digest alloc] initWithInputData:inputData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertEqualObjects(expectedOutputData, op.outputDigest, @"");
}

- (void)testHMACSHA1Authentication
{
    NSData *                    inputData;
    NSData *                    keyData;
    QCCHMACSHA1Authentication * op;
    NSData *                    expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(inputData != nil);
    
    keyData = [QHex dataWithHexString:@"48656c6c6f20437275656c20576f726c6421"];
    assert(keyData != nil);
    
    expectedOutputData = [QHex dataWithHexString:@"550a1da058c1b5df6ea167870ae6dbc92f0e0281"];
    assert(expectedOutputData != nil);
    
    op = [[QCCHMACSHA1Authentication alloc] initWithInputData:inputData keyData:keyData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertEqualObjects(expectedOutputData, op.outputHMAC, @"");
}

- (void)testHMACSHA1AuthenticationEmptyKey
{
    NSData *                    inputData;
    NSData *                    keyData;
    QCCHMACSHA1Authentication * op;
    NSData *                    expectedOutputData;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(inputData != nil);
    
    keyData = [NSData data];
    assert(keyData != nil);
    
    expectedOutputData = [QHex dataWithHexString:@"4d38e8a1ea27cb89a3ce3f0df8de45b5e5820c6a"];
    assert(expectedOutputData != nil);
    
    op = [[QCCHMACSHA1Authentication alloc] initWithInputData:inputData keyData:keyData];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertEqualObjects(expectedOutputData, op.outputHMAC, @"");
}

- (void)testDigestThrows
{
    STAssertThrows((void) [[QCCMD5Digest alloc] initWithInputData:nil], @"");
    STAssertThrows((void) [[QCCSHA1Digest alloc] initWithInputData:nil], @"");
    STAssertThrows((void) [[QCCHMACSHA1Authentication alloc] initWithInputData:nil keyData:[NSData data]], @"");
    STAssertThrows((void) [[QCCHMACSHA1Authentication alloc] initWithInputData:[NSData data] keyData:nil], @"");
}

@end
