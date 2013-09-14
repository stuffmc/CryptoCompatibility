/*
     File: Base64OperationsTests.m
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

#import "Base64OperationsTests.h"

#import "QCCBase64Encode.h"
#import "QCCBase64Decode.h"

#import "ToolCommon.h"

@implementation Base64OperationsTests

- (void)setUp
{
    [super setUp];
    [ToolCommon sharedInstance].debugRunOpOnMainThread = YES;
}

- (void)testBase64Encode
{
    NSData *            inputData;
    QCCBase64Encode *   op;
    NSString *          expectedOutputString;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(inputData != nil);
    
    expectedOutputString = [NSString stringWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"pem"] encoding:NSUTF8StringEncoding error:NULL];
    assert(expectedOutputString != nil);
    
    op = [[QCCBase64Encode alloc] initWithInputData:inputData];
    op.addLineBreaks = YES;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertEqualObjects(expectedOutputString, op.outputString, @"");
}

- (void)testBase64EncodeEmpty
{
    NSData *            inputData;
    QCCBase64Encode *   op;
    NSString *          expectedOutputString;
    
    inputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"plaintext-0" withExtension:@"dat"]];
    assert(inputData != nil);
    
    expectedOutputString = @"";
    assert(expectedOutputString != nil);
    
    op = [[QCCBase64Encode alloc] initWithInputData:inputData];
    op.addLineBreaks = YES;
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertEqualObjects(expectedOutputString, op.outputString, @"");
}

- (void)testBase64Decode
{
    NSString *          inputString;
    QCCBase64Decode *   op;
    NSData *            expectedOutputData;
    
    inputString = [NSString stringWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"pem"] encoding:NSUTF8StringEncoding error:NULL];
    assert(inputString != nil);
    
    expectedOutputData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:@"test" withExtension:@"cer"]];
    assert(expectedOutputData != nil);
    
    op = [[QCCBase64Decode alloc] initWithInputString:inputString];
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    STAssertEqualObjects(expectedOutputData, op.outputData, @"");
}

- (void)testBase64Throws
{
    STAssertThrows((void) [[QCCBase64Encode alloc] initWithInputData:nil], @"");
    STAssertThrows((void) [[QCCBase64Decode alloc] initWithInputString:nil], @"");
}

@end
