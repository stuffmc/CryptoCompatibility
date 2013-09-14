/*
     File: DigestCommands.m
 Abstract: Commands for MD5 and other digests.
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

#import "DigestCommands.h"

#import "QCCMD5Digest.h"
#import "QCCSHA1Digest.h"
#import "QCCHMACSHA1Authentication.h"

#import "ToolCommon.h"

#import "QHex.h"

@interface DigestCommand ()

+ (Class)digestOperationClass;

@end

@implementation DigestCommand

+ (Class)digestOperationClass
{
    NSAssert(NO, @"implementation required");
    return nil;
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
    NSData *    data;
    
    data = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:self.arguments[0]] options:0 error:errorPtr];
    success = (data != nil);
    
    if (success) {
        QCCMD5Digest *      op;
        
        // We're playing fast'n'loose with types here.  The various digest operations 
        // don't share a command base class (becasue I don't want to have them coupled together) 
        // so we don't have a class we can use for "op".  Rather than write lots of pointless 
        // code just to keep the compiler happy, I tell the compile that "op" is of type 
        // QCCMD5Digest.  In reality it could be any of the other digest classes.
        
        op = [[[[self class] digestOperationClass] alloc] initWithInputData:data];
        [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
        fprintf(stdout, "%s\n", [[QHex hexStringWithData:op.outputDigest] UTF8String]);
    }
    
    return success;
}

@end

@implementation MD5DigestCommand

+ (NSString *)commandName
{
    return @"md5-digest";
}

+ (Class)digestOperationClass
{
    return [QCCMD5Digest class];
}

@end

@implementation SHA1DigestCommand

+ (NSString *)commandName
{
    return @"sha1-digest";
}

+ (Class)digestOperationClass
{
    return [QCCSHA1Digest class];
}

@end

@interface SHA1HMACCommand ()

@property (nonatomic, copy,   readwrite) NSData *       keyData;

@end

@implementation SHA1HMACCommand

+ (NSString *)commandName
{
    return @"hmac-sha1";
}

+ (NSString *)commandUsage
{
    return [NSString stringWithFormat:@"%@ -k keyHexStr file", [self commandName]];
}

- (NSString *)commandOptions
{
    return @"k:";
}

- (BOOL)setOption_k_argument:(NSString *)argument
{
    self.keyData = [QHex dataWithHexString:argument];
    return (self.keyData != nil);
}

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments
{
    BOOL    success;
    
    success = [super validateOptionsAndArguments:optionsAndArguments];
    if (success) {
        if ([self.arguments count] != 1) {
            success = NO;
        } else if (self.keyData == nil) {
            success = NO;
        }
    }
    return success;
}

- (BOOL)runError:(NSError **)errorPtr
{
    BOOL        success;
    NSData *    data;
    
    data = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:self.arguments[0]] options:0 error:errorPtr];
    success = (data != nil);
    
    if (success) {
        QCCHMACSHA1Authentication *     op;
        
        op = [[QCCHMACSHA1Authentication alloc] initWithInputData:data keyData:self.keyData];
        [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
        fprintf(stdout, "%s\n", [[QHex hexStringWithData:op.outputHMAC] UTF8String]);
    }
    
    return success;
}

@end
