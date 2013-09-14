/*
     File: main.m
 Abstract: Command line tool main.
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

#import <Foundation/Foundation.h>

#import "Base64Commands.h"
#import "DigestCommands.h"
#import "KeyDerivationCommands.h"
#import "CryptorCommands.h"
#import "RSACommands.h"

#import "ToolCommon.h"

#import "QToolCommand.h"

@interface MainCommand : QComplexToolCommand

@property (nonatomic, assign, readwrite) NSUInteger verbose;
@property (nonatomic, assign, readwrite) BOOL       debug;

@end

@implementation MainCommand

+ (NSArray *)subcommandClasses
{
    return @[
        [Base64EncodeCommand class], 
        [Base64DecodeCommand class],
        [SHA1DigestCommand class],
        [MD5DigestCommand class],
        [SHA1HMACCommand class], 
        [PBKDF2KeyDerivationCommand class], 
        [AESEncryptCommand class], 
        [AESDecryptCommand class], 
        [AESPadEncryptCommand class], 
        [AESPadDecryptCommand class], 
        [AESPadBigEncryptCommand class], 
        [AESPadBigDecryptCommand class], 
        [RSASHA1VerifyCommand class], 
        [RSASHA1SignCommand class], 
        [RSASmallEncryptCommand class], 
        [RSASmallDecryptCommand class]
    ];
}

+ (NSString *)commandName
{
    return [[NSString alloc] initWithUTF8String:getprogname()];
}

+ (NSString *)commandUsage
{
    return [[NSString alloc] initWithFormat:@"%@ [-v] subcommand\n"
        "\n"
        "Subcommands:\n"
        "\n"
        "%@", 
        [self commandName], 
        [super commandUsage]
    ];
}

- (NSString *)commandOptions
{
    return @"vd";
}

- (void)setOption_v
{
    self.verbose += 1;
}

- (void)setOption_d
{
    self.debug = YES;
}

@end

int main(int argc, char **argv)
{
    #pragma unused(argc)
    #pragma unused(argv)
    BOOL        success;

    @autoreleasepool {
        MainCommand *   mainCommand;
        
        mainCommand = [[MainCommand alloc] init];
        success = [mainCommand validateOptionsAndArguments:[QToolCommand optionsAndArgumentsFromArgC:argc argV:argv]];
        
        if ( ! success ) {
            fprintf(stderr, "usage: %s\n\n", [[[mainCommand class] commandUsage] UTF8String]);
        } else {
            NSError *       error;
            
            if (mainCommand.debug) {
                [ToolCommon sharedInstance].debugRunOpOnMainThread = YES;
            }
            success = [mainCommand runError:&error];
            if (success) {
                if (mainCommand.verbose != 0) {
                    fprintf(stderr, "Success!\n");
                }
            } else {
                fprintf(stderr, "%s: error: %s / %d\n", [[[mainCommand class] commandName] UTF8String], [[error domain] UTF8String], (int) [error code]);
            }
        }
    }

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
