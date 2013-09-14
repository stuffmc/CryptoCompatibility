/*
     File: Base64Commands.m
 Abstract: Commands for Base64 encode and decode.
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

#import "Base64Commands.h"

#import "QCCBase64Encode.h"
#import "QCCBase64Decode.h"

#import "ToolCommon.h"

@interface Base64EncodeCommand ()

@property (nonatomic, assign, readwrite) BOOL   addLineBreaks;

@end

@implementation Base64EncodeCommand

+ (NSString *)commandName
{
    return @"base64-encode";
}

+ (NSString *)commandUsage
{
    return [NSString stringWithFormat:@"%@ [-l] file", [self commandName]];
}

- (NSString *)commandOptions
{
    return @"l";
}

- (void)setOption_l
{
    self.addLineBreaks = YES;
}

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments
{
    BOOL    success;
    
    success = [super validateOptionsAndArguments:optionsAndArguments];
    if (success && ([self.arguments count] != 1)) {
        success = NO;
    }
    return success;
}

- (BOOL)runError:(NSError **)errorPtr
{
    BOOL        success;
    NSData *    fileData;
    
    fileData = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:self.arguments[0]] options:0 error:errorPtr];
    success = (fileData != nil);
    
    if (success) {
        QCCBase64Encode *   op;
        
        op = [[QCCBase64Encode alloc] initWithInputData:fileData];
        op.addLineBreaks = self.addLineBreaks;
        [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
        fprintf(stdout, "%s", [op.outputString UTF8String]);
    }
    
    return success;
}

@end

@implementation Base64DecodeCommand

+ (NSString *)commandName
{
    return @"base64-decode";
}

+ (NSString *)commandUsage
{
    return [NSString stringWithFormat:@"%@ file", [self commandName]];
}

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments
{
    BOOL    success;
    
    success = [super validateOptionsAndArguments:optionsAndArguments];
    if (success && ([self.arguments count] != 1)) {
        success = NO;
    }
    return success;
}

- (BOOL)runError:(NSError **)errorPtr
{
    BOOL        success;
    NSString *  fileString;
    
    fileString = [NSString stringWithContentsOfURL:[NSURL fileURLWithPath:self.arguments[0]] encoding:NSUTF8StringEncoding error:errorPtr];
    success = (fileString != nil);
    
    if (success) {
        QCCBase64Decode *   op;
        
        op = [[QCCBase64Decode alloc] initWithInputString:fileString];
        [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
        if (op.outputData == nil) {
            success = NO;
            if (errorPtr != NULL) {
                *errorPtr = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadCorruptFileError userInfo:nil];
            }
        } else {
            (void) fwrite([op.outputData bytes], [op.outputData length], 1, stdout);
        }
    }
    
    return success;
}

@end

