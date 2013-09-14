/*
     File: RSACommands.m
 Abstract: Commands for RSA-based encryption, decryption, signing, and verification.
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

#import "RSACommands.h"

#import "QCCRSASHA1VerifyT.h"
#import "QCCRSASHA1SignT.h"
#import "QCCRSASmallCryptorT.h"

#import "ToolCommon.h"

#import "QHex.h"

static SecKeyRef CopyKeyOfClassAndName(CFStringRef keyClass, NSString * keyName, NSError **errorPtr)
{
    OSStatus        err;
    CFTypeRef       matchResult;
    SecKeyRef       key;
    
    key = NULL;
    
    err = SecItemCopyMatching((__bridge CFDictionaryRef) @{
            (__bridge id) kSecClass:        (__bridge id) kSecClassKey,
            (__bridge id) kSecReturnRef:    (__bridge id) kCFBooleanTrue, 
            (__bridge id) kSecAttrKeyClass: (__bridge id) keyClass, 
            (__bridge id) kSecAttrKeyType:  (__bridge id) kSecAttrKeyTypeRSA,
            (__bridge id) kSecAttrLabel:                  keyName
        }, 
        &matchResult
    );
    if (err == errSecSuccess) {
        assert(CFGetTypeID(matchResult) == SecKeyGetTypeID());
        key = (SecKeyRef) matchResult;
        CFRetain(key);
        CFRelease(matchResult);
    } else if (errorPtr != NULL) {
        *errorPtr = [NSError errorWithDomain:NSPOSIXErrorDomain code:err userInfo:nil];
    }
    return key;
}

static SecKeyRef CopyPublicKeyNamed(NSString * publicKeyName, NSError **errorPtr)
{
    return CopyKeyOfClassAndName(kSecAttrKeyClassPublic, publicKeyName, errorPtr);
}

static SecKeyRef CopyPrivateKeyNamed(NSString * privateKeyName, NSError **errorPtr)
{
    return CopyKeyOfClassAndName(kSecAttrKeyClassPrivate, privateKeyName, errorPtr); 
}

@implementation RSASHA1VerifyCommand

+ (NSString *)commandName
{
    return @"rsa-sha1-verify";
}

+ (NSString *)commandUsage
{
    return [NSString stringWithFormat:@"%@ publicKeyName signatureFile dataFile", [self commandName]];
}

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments
{
    BOOL    success;
    
    success = [super validateOptionsAndArguments:optionsAndArguments];
    if (success && ([self.arguments count] != 3)) {
        success = NO;
    }
    return success;
}

- (BOOL)runError:(NSError **)errorPtr
{
    BOOL        success;
    NSString *  publicKeyName;
    NSData *    signatureData;
    NSData *    fileData;
    SecKeyRef   publicKey;
    
    publicKey = NULL;
    
    publicKeyName = self.arguments[0];
    signatureData = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:self.arguments[1]] options:0 error:errorPtr];
    success = (signatureData != nil);
    if (success) {
        fileData = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:self.arguments[2]] options:0 error:errorPtr];
        success = (fileData != nil);
    }
    
    if (success) {
        publicKey = CopyPublicKeyNamed(publicKeyName, errorPtr);
        success = (publicKey != NULL);
    }
    
    if (success) {
        QCCRSASHA1VerifyT * op;
        
        op = [[QCCRSASHA1VerifyT alloc] initWithInputData:fileData publicKey:publicKey signatureData:signatureData];
        [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
        success = (op.error == nil);
        if (success) {
            if (op.verified) {
                fprintf(stdout, "verified\n");
            } else {
                fprintf(stdout, "not verified\n");
            }
        } else if (errorPtr != NULL) {
            *errorPtr = op.error;
        }
    }
    
    if (publicKey != NULL) {
        CFRelease(publicKey);
    }
    
    return success;
}

@end

@implementation RSASHA1SignCommand

+ (NSString *)commandName
{
    return @"rsa-sha1-sign";
}

+ (NSString *)commandUsage
{
    return [NSString stringWithFormat:@"%@ privateKeyName file", [self commandName]];
}

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments
{
    BOOL    success;
    
    success = [super validateOptionsAndArguments:optionsAndArguments];
    if (success && ([self.arguments count] != 2)) {
        success = NO;
    }
    return success;
}

- (BOOL)runError:(NSError **)errorPtr
{
    BOOL        success;
    NSString *  privateKeyName;
    NSData *    fileData;
    SecKeyRef   privateKey;
    
    privateKey = NULL;
    
    privateKeyName = self.arguments[0];
    fileData = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:self.arguments[1]] options:0 error:errorPtr];
    success = (fileData != nil);
    
    if (success) {
        privateKey = CopyPrivateKeyNamed(privateKeyName, errorPtr);
        success = (privateKey != NULL);
    }
    
    if (success) {
        QCCRSASHA1SignT *   op;
        
        op = [[QCCRSASHA1SignT alloc] initWithInputData:fileData privateKey:privateKey];
        [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
        success = (op.error == nil);
        if (success) {
            fprintf(stdout, "%s\n", [[QHex hexStringWithData:op.signatureData] UTF8String]);
        } else if (errorPtr != NULL) {
            *errorPtr = op.error;
        }
    }
    
    if (privateKey != NULL) {
        CFRelease(privateKey);
    }
    
    return success;
}

@end

@interface RSACryptorCommand ()

@property (nonatomic, assign, readwrite) QCCRSASmallCryptorTPadding padding;

@end

@implementation RSACryptorCommand

- (id)init
{
    self = [super init];
    if (self != nil) {
        self->_padding = kQCCRSASmallCryptorTPaddingPKCS1;
    }
    return self;
}

- (NSString *)commandOptions
{
    return @"p:";
}

- (BOOL)setOption_p_argument:(NSString *)argument
{
    BOOL    result;
    
    result = YES;
    if ([argument isEqual:@"none"]) {
        self.padding = kQCCRSASmallCryptorTPaddingNone;
    } else if ([argument isEqual:@"pkcs1"]) {
        self.padding = kQCCRSASmallCryptorTPaddingPKCS1;
    } else {
        result = NO;
    }
    return result;
}

@end

@interface RSASmallEncryptCommand ()

@end

@implementation RSASmallEncryptCommand

+ (NSString *)commandName
{
    return @"rsa-small-encrypt";
}

+ (NSString *)commandUsage
{
    return [NSString stringWithFormat:@"%@ [-p none|pkcs1] publicKeyName file", [self commandName]];
}

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments
{
    BOOL    success;
    
    success = [super validateOptionsAndArguments:optionsAndArguments];
    if (success && ([self.arguments count] != 2)) {
        success = NO;
    }
    return success;
}

- (BOOL)runError:(NSError **)errorPtr
{
    BOOL        success;
    NSString *  publicKeyName;
    NSData *    fileData;
    SecKeyRef   publicKey;
    
    publicKey = NULL;
    
    publicKeyName = self.arguments[0];
    fileData = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:self.arguments[1]] options:0 error:errorPtr];
    success = (fileData != nil);
    
    if (success) {
        publicKey = CopyPublicKeyNamed(publicKeyName, errorPtr);
        success = (publicKey != NULL);
    }
    
    if (success) {
        QCCRSASmallCryptorT *   op;
        
        op = [[QCCRSASmallCryptorT alloc] initToEncryptSmallInputData:fileData key:publicKey];
        op.padding = self.padding;
        [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
        success = (op.error == nil);
        if (success) {
            fprintf(stdout, "%s\n", [[QHex hexStringWithData:op.smallOutputData] UTF8String]);
        } else if (errorPtr != NULL) {
            *errorPtr = op.error;
        }
    }
    
    if (publicKey != NULL) {
        CFRelease(publicKey);
    }
    
    return success;
}

@end

@interface RSASmallDecryptCommand ()

@property (nonatomic, assign, readwrite) QCCRSASmallCryptorTPadding padding;

@end

@implementation RSASmallDecryptCommand

+ (NSString *)commandName
{
    return @"rsa-small-decrypt";
}

+ (NSString *)commandUsage
{
    return [NSString stringWithFormat:@"%@ [-p none|pkcs1] privateKeyName file", [self commandName]];
}

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments
{
    BOOL    success;
    
    success = [super validateOptionsAndArguments:optionsAndArguments];
    if (success && ([self.arguments count] != 2)) {
        success = NO;
    }
    return success;
}

- (BOOL)runError:(NSError **)errorPtr
{
    BOOL        success;
    NSString *  privateKeyName;
    NSData *    fileData;
    SecKeyRef   privateKey;
    
    privateKey = NULL;
    
    privateKeyName = self.arguments[0];
    fileData = [NSData dataWithContentsOfURL:[NSURL fileURLWithPath:self.arguments[1]] options:0 error:errorPtr];
    success = (fileData != nil);
    
    if (success) {
        privateKey = CopyPrivateKeyNamed(privateKeyName, errorPtr);
        success = (privateKey != NULL);
    }
    
    if (success) {
        QCCRSASmallCryptorT *   op;
        
        op = [[QCCRSASmallCryptorT alloc] initToDecryptSmallInputData:fileData key:privateKey];
        op.padding = self.padding;
        [[ToolCommon sharedInstance] synchronouslyRunOperation:op];
        success = (op.error == nil);
        if (success) {
            fprintf(stdout, "%s\n", [[QHex hexStringWithData:op.smallOutputData] UTF8String]);
        } else if (errorPtr != NULL) {
            *errorPtr = op.error;
        }
    }
    
    if (privateKey != NULL) {
        CFRelease(privateKey);
    }
    
    return success;
}

@end
