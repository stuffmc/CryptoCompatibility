/*
     File: KeyDerivationOperationsTests.m
 Abstract: Tests for the key derivation operations.
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

#import "KeyDerivationOperationsTests.h"

#import "QCCPBKDF2SHA1KeyDerivation.h"

#import "ToolCommon.h"

#import "QHex.h"

#import <CommonCrypto/CommonCrypto.h>

@implementation KeyDerivationOperationsTests

- (void)setUp
{
    [super setUp];
    [ToolCommon sharedInstance].debugRunOpOnMainThread = YES;
}

- (void)testPBKDF2
{
    QCCPBKDF2SHA1KeyDerivation *    op;
    NSString *                      passwordString;
    NSData *                        saltData;
    NSData *                        expectedKeyData;
    
    passwordString = @"Hello Cruel World!";
    assert(passwordString != nil);
    
    saltData = [@"Some salt sir?" dataUsingEncoding:NSUTF8StringEncoding];
    assert(saltData != nil);

    // This result was generated with PHP 5.5.0.a6 using:
    // 
    // hash_pbkdf2("sha1", "Hello Cruel World!", "Some salt sir?", 1000, 10, true);
    
    expectedKeyData = [QHex dataWithHexString:@"e56c27f5eed251db50a3"];
    assert(expectedKeyData != nil);
    
    op = [[QCCPBKDF2SHA1KeyDerivation alloc] initWithPasswordString:passwordString saltData:saltData];
    op.rounds = 1000;
    op.derivedKeyLength = 10;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(op.derivedKeyData, expectedKeyData, @"");
}

- (void)testPBKDF2EmptySalt
{
    QCCPBKDF2SHA1KeyDerivation *    op;
    NSString *                      passwordString;
    NSData *                        saltData;
    NSData *                        expectedKeyData;
    
    // Note: This test fails on OS X 10.7.x and iOS 5.x because CCKeyDerivationPBKDF returns 
    // an error if there's no salt.
    
    passwordString = @"Hello Cruel World!";
    assert(passwordString != nil);
    
    saltData = [NSData data];
    assert(saltData != nil);

    // This result was generated with PHP 5.5.0.a6 using:
    // 
    // hash_pbkdf2("sha1", "Hello Cruel World!", "", 1000, 10, true);
    
    expectedKeyData = [QHex dataWithHexString:@"98b4c8aec38c64c8e2de"];
    assert(expectedKeyData != nil);
    
    op = [[QCCPBKDF2SHA1KeyDerivation alloc] initWithPasswordString:passwordString saltData:saltData];
    op.rounds = 1000;
    op.derivedKeyLength = 10;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(op.derivedKeyData, expectedKeyData, @"");
}

- (void)testPBKDF2Empty
{
    QCCPBKDF2SHA1KeyDerivation *    op;
    NSString *                      passwordString;
    NSData *                        saltData;
    NSData *                        expectedKeyData;
    
    // Note: This test fails on OS X 10.7.x and iOS 5.x because CCKeyDerivationPBKDF returns 
    // an error if there's no salt.
    
    passwordString = @"";
    assert(passwordString != nil);
    
    saltData = [NSData data];
    assert(saltData != nil);

    // This result was generated with PHP 5.5.0.a6 using:
    // 
    // hash_pbkdf2("sha1", "", "", 1000, 10, true);
    
    expectedKeyData = [QHex dataWithHexString:@"6e40910ac02ec89cebb9"];
    assert(expectedKeyData != nil);
    
    op = [[QCCPBKDF2SHA1KeyDerivation alloc] initWithPasswordString:passwordString saltData:saltData];
    op.rounds = 1000;
    op.derivedKeyLength = 10;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertEqualObjects(op.derivedKeyData, expectedKeyData, @"");
}

- (void)testPBKDF2Calibration
{
    NSString *                      passwordString;
    NSData *                        saltData;
    QCCPBKDF2SHA1KeyDerivation *    op;
    NSData *                        derivedKey;
    NSUInteger                      actualRounds;
    NSTimeInterval                  startTime;
    NSTimeInterval                  timeTaken;
    
    passwordString = @"Hello Cruel World!";
    assert(passwordString != nil);
    
    saltData = [@"Some salt sir?" dataUsingEncoding:NSUTF8StringEncoding];
    assert(saltData != nil);
        
    // First run the operation with a target time (0.5 seconds).
    
    op = [[QCCPBKDF2SHA1KeyDerivation alloc] initWithPasswordString:passwordString saltData:saltData];
    op.derivationTime = 0.5;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNil(op.error, @"");
    STAssertNotNil(op.derivedKeyData, @"");
    derivedKey = op.derivedKeyData;
    actualRounds = op.actualRounds;
    
    // Then run it again with the rounds from the previous operation. 
    // It should take (roughly) 0.5 seconds.  If it doesn't, that's a problem.
    //
    // Note we have a huge time variance here due, so we accept a large range of values.
    
    op = [[QCCPBKDF2SHA1KeyDerivation alloc] initWithPasswordString:passwordString saltData:saltData];
    op.rounds = actualRounds;
    startTime = [NSDate timeIntervalSinceReferenceDate];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    timeTaken = [NSDate timeIntervalSinceReferenceDate] - startTime;
    STAssertNil(op.error, @"");
    STAssertEqualsWithAccuracy(timeTaken, 0.5, 0.2, @"");
    STAssertEquals(op.actualRounds, actualRounds, @"");
    STAssertEqualObjects(op.derivedKeyData, derivedKey, @"");
}

- (void)testPBKDF2Error
{
    NSString *                      passwordString;
    NSData *                        saltData;
    QCCPBKDF2SHA1KeyDerivation *    op;

    passwordString = @"Hello Cruel World!";
    assert(passwordString != nil);
    
    saltData = [@"Some salt sir?" dataUsingEncoding:NSUTF8StringEncoding];
    assert(saltData != nil);
        
    // a derived key length of zero is not valid
    
    op = [[QCCPBKDF2SHA1KeyDerivation alloc] initWithPasswordString:passwordString saltData:saltData];
    op.derivedKeyLength = 0;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCPBKDF2KeyDerivationErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.derivedKeyData, @"");

    // repeat the above with a rounds value, which triggers the error in a different place
    
    op = [[QCCPBKDF2SHA1KeyDerivation alloc] initWithPasswordString:passwordString saltData:saltData];
    op.derivedKeyLength = 0;
    op.rounds = 1000;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertNotNil(op.error, @"");
    STAssertEqualObjects([op.error domain], kQCCPBKDF2KeyDerivationErrorDomain, @"");
    STAssertEquals([op.error code], (NSInteger) kCCParamError, @"");
    STAssertNil(op.derivedKeyData, @"");
}

- (void)testKeyDerivationThrows
{
    STAssertThrows((void) [[QCCPBKDF2SHA1KeyDerivation alloc] initWithPasswordString:nil saltData:[NSData data]], @"");
    STAssertThrows((void) [[QCCPBKDF2SHA1KeyDerivation alloc] initWithPasswordString:[NSData data] saltData:nil], @"");
}

@end
