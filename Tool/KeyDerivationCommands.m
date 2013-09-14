/*
     File: KeyDerivationCommands.m
 Abstract: Commands for key derivation.
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

#import "KeyDerivationCommands.h"

#import "QCCPBKDF2SHA1KeyDerivation.h"

#import "ToolCommon.h"

#import "QHex.h"

@interface PBKDF2KeyDerivationCommand ()

@property (nonatomic, copy,   readwrite) NSString *     passwordString;
@property (nonatomic, copy,   readwrite) NSData *       saltData;
@property (nonatomic, assign, readwrite) NSInteger      rounds;
@property (nonatomic, assign, readwrite) NSInteger      derivedKeyLength;

@end

@implementation PBKDF2KeyDerivationCommand

+ (NSString *)commandName
{
    return @"pbkdf2-sha1-key-derivation";
}

+ (NSString *)commandUsage
{
    return [NSString stringWithFormat:@"%@ -p passwordStr -s saltHexStr [-r rounds] [-z derivedKeyLength] file", [self commandName]];
}

- (NSString *)commandOptions
{
    return @"p:s:r:z:";
}

- (BOOL)setOption_p_argument:(NSString *)argument
{
    self.passwordString = argument;
    return YES;
}

- (BOOL)setOption_s_argument:(NSString *)argument
{
    self.saltData = [QHex dataWithHexString:argument];
    return (self.saltData != nil);
}

- (BOOL)setOption_r_argument:(NSString *)argument
{
    self.rounds = [argument integerValue];
    return (self.rounds >= 0);
}

- (BOOL)setOption_z_argument:(NSString *)argument
{
    self.derivedKeyLength = [argument integerValue];
    return (self.derivedKeyLength >= 0);
}

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments
{
    BOOL    success;
    
    success = [super validateOptionsAndArguments:optionsAndArguments];
    if (success) {
        if ([self.arguments count] != 0) {
            success = NO;
        } else if (self.passwordString == nil) {
            success = NO;
        } else if (self.saltData == nil) {
            success = NO;
        }
    }
    return success;
}

- (BOOL)runError:(NSError **)errorPtr
{
    BOOL                            success;
    QCCPBKDF2SHA1KeyDerivation *    op;
    
    success = YES;
    op = [[QCCPBKDF2SHA1KeyDerivation alloc] initWithPasswordString:self.passwordString saltData:self.saltData];
    if (self.rounds != 0) {
        op.rounds = self.rounds;
    }
    if (self.derivedKeyLength != 0) {
        op.derivedKeyLength = self.derivedKeyLength;
    }
    [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
    if (op.error == nil) {
        fprintf(stdout, "%s\n", [[QHex hexStringWithData:op.derivedKeyData] UTF8String]);
    } else {
        if (errorPtr != NULL) {
            *errorPtr = op.error;
        }
        success = NO;
    }
    
    return success;
}

@end
