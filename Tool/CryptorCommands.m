/*
     File: CryptorCommands.m
 Abstract: Commands for symmetric encryption and decryption.
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

#import "CryptorCommands.h"

#import "QCCAESCryptor.h"
#import "QCCAESPadCryptor.h"
#import "QCCAESPadBigCryptor.h"

#import "ToolCommon.h"

#import "QHex.h"

@interface AESCryptorCommand ()

@property (nonatomic, copy,   readwrite) NSData *       keyData;
@property (nonatomic, copy,   readwrite) NSData *       ivData;
@property (nonatomic, assign, readwrite) BOOL           ecbMode;

// for subclasses to implement

+ (Class)cryptorClass;
+ (BOOL)encrypt;
- (BOOL)validateArguments;

@end

@implementation AESCryptorCommand

+ (Class)cryptorClass
{
    NSAssert(NO, @"implementation required");
    return nil;
}

+ (BOOL)encrypt
{
    NSAssert(NO, @"implementation required");
    return YES;
}

- (BOOL)validateArguments
{
    return ([self.arguments count] == 1);
}

+ (NSString *)commandUsage
{
    return [NSString stringWithFormat:@"%@ -k keyHexStr (-e | [-i ivHexStr]) file", [self commandName]];
}

- (NSString *)commandOptions
{
    return @"k:i:e";
}

- (BOOL)setOption_k_argument:(NSString *)argument
{
    self.keyData = [QHex dataWithHexString:argument];
    return (self.keyData != nil);
}

- (BOOL)setOption_i_argument:(NSString *)argument
{
    self.ivData = [QHex dataWithHexString:argument];
    return (self.ivData != nil);
}

- (void)setOption_e
{
    self.ecbMode = YES;
}

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments
{
    BOOL    success;
    
    success = [super validateOptionsAndArguments:optionsAndArguments];
    if (success) {
        if ( ! [self validateArguments] ) {
            success = NO;
        } else if (self.keyData == nil) {
            success = NO;
        } else if (self.ecbMode && (self.ivData != nil)) {
            success = NO;           // IV is incompatible with ECB
        }
    }
    return success;
}

- (BOOL)runError:(NSError **)errorPtr
{
    BOOL                success;
    NSData *            fileData;
    QCCAESCryptor *     op;

    fileData = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:self.arguments[0]] options:0 error:errorPtr];
    success = (fileData != nil);
    
    if (success) {
        // We're playing fast'n'loose with types here.  The various cryptor operations 
        // don't share a command base class (becasue I don't want to have them coupled together) 
        // so we don't have a class we can use for "op".  Rather than write lots of pointless 
        // code just to keep the compiler happy, I tell the compile that "op" is of type 
        // QCCAESCryptor.  In reality it could be any of the other cryptor classes.

        if ([[self class] encrypt]) {
            op = [[[[self class] cryptorClass] alloc] initToEncryptInputData:fileData keyData:self.keyData];
        } else {
            op = [[[[self class] cryptorClass] alloc] initToDecryptInputData:fileData keyData:self.keyData];
        }
        if (self.ecbMode) {
            op.ivData = nil;
        } else if (self.ivData != nil) {
            op.ivData = self.ivData;
        }
        [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
        if (op.error == nil) {
            (void) fwrite([op.outputData bytes], [op.outputData length], 1, stdout);
        } else {
            if (errorPtr != NULL) {
                *errorPtr = op.error;
            }
            success = NO;
        }
    }
    
    return success;
}

@end

@implementation AESEncryptCommand

+ (NSString *)commandName
{
    return @"aes-encrypt";
}

+ (Class)cryptorClass
{
    return [QCCAESCryptor class];
}

+ (BOOL)encrypt
{
    return YES;
}

@end

@implementation AESDecryptCommand

+ (NSString *)commandName
{
    return @"aes-decrypt";
}

+ (Class)cryptorClass
{
    return [QCCAESCryptor class];
}

+ (BOOL)encrypt
{
    return NO;
}

@end

@implementation AESPadEncryptCommand

+ (NSString *)commandName
{
    return @"aes-pad-encrypt";
}

+ (Class)cryptorClass
{
    return [QCCAESPadCryptor class];
}

+ (BOOL)encrypt
{
    return YES;
}

@end

@implementation AESPadDecryptCommand

+ (NSString *)commandName
{
    return @"aes-pad-decrypt";
}

+ (Class)cryptorClass
{
    return [QCCAESPadCryptor class];
}

+ (BOOL)encrypt
{
    return NO;
}

@end

@implementation AESBigCryptorCommand

- (BOOL)validateArguments
{
    return ([self.arguments count] == 2);
}

+ (NSString *)commandUsage
{
    return [NSString stringWithFormat:@"%@ -k keyHexStr (-e | [-i ivHexStr]) inputFile outputFile", [self commandName]];
}

- (BOOL)runError:(NSError **)errorPtr
{
    BOOL                    success;
    NSInputStream *         inputStream;
    NSOutputStream *        outputStream;
    QCCAESPadBigCryptor *   op;

    inputStream = [NSInputStream inputStreamWithFileAtPath:self.arguments[0]];
    success = (inputStream != nil);

    if (success) {
        outputStream = [NSOutputStream outputStreamToFileAtPath:self.arguments[1] append:NO];
        success = (outputStream != nil);
    }
    
    if (success) {
        // We're playing fast'n'loose with types here.  The various cryptor operations 
        // don't share a command base class (becasue I don't want to have them coupled together) 
        // so we don't have a class we can use for "op".  Rather than write lots of pointless 
        // code just to keep the compiler happy, I tell the compile that "op" is of type 
        // QCCAESPadBigCryptor.  In reality it could be any of the other cryptor classes.

        if ([[self class] encrypt]) {
            op = [[[[self class] cryptorClass] alloc] initToEncryptInputStream:inputStream toOutputStream:outputStream keyData:self.keyData];
        } else {
            op = [[[[self class] cryptorClass] alloc] initToDecryptInputStream:inputStream toOutputStream:outputStream keyData:self.keyData];
        }
        if (self.ecbMode) {
            op.ivData = nil;
        } else if (self.ivData != nil) {
            op.ivData = self.ivData;
        }
        [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
        if (op.error != nil) {
            if (errorPtr != NULL) {
                *errorPtr = op.error;
            }
            success = NO;
        }
    }
    
    return success;
}

@end

@implementation AESPadBigEncryptCommand

+ (NSString *)commandName
{
    return @"aes-pad-big-encrypt";
}

+ (Class)cryptorClass
{
    return [QCCAESPadBigCryptor class];
}

+ (BOOL)encrypt
{
    return YES;
}

@end

@implementation AESPadBigDecryptCommand

+ (NSString *)commandName
{
    return @"aes-pad-big-decrypt";
}

+ (Class)cryptorClass
{
    return [QCCAESPadBigCryptor class];
}

+ (BOOL)encrypt
{
    return NO;
}

@end
