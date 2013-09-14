/*
     File: QCCPBKDF2SHA1KeyDerivation.m
 Abstract: Uses PBKDF2 to derive a key from a password string.
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

#import "QCCPBKDF2SHA1KeyDerivation.h"

#include <CommonCrypto/CommonCrypto.h>

@interface QCCPBKDF2SHA1KeyDerivation ()

// read/write versions of public properties

@property (atomic, copy,   readwrite) NSError *         error;
@property (atomic, assign, readwrite) NSUInteger        actualRounds;
@property (atomic, copy,   readwrite) NSData *          derivedKeyData;

@end

@implementation QCCPBKDF2SHA1KeyDerivation

- (id)initWithPasswordString:(NSString *)passwordString saltData:(NSData *)saltData
{
    NSParameterAssert(passwordString != nil);
    NSParameterAssert(saltData != nil);
    self = [super init];
    if (self != nil) {
        self->_passwordString = [passwordString copy];
        self->_saltData = [saltData copy];
        self->_rounds = 0;
        self->_derivationTime = 0.1;
        self->_derivedKeyLength = 16;
    }
    return self;
}

- (void)calculateActualRoundsForPasswordLength:(size_t)passwordLength saltLength:(size_t)saltLength
{
    unsigned int        result;
    double              derivationTimeMilliseconds;
    
    derivationTimeMilliseconds = self.derivationTime * 1000.0;
    
    // CCCalibratePBKDF has undocumented limits on the salt length <rdar://problem/13641064>.
    
    if (saltLength == 0) {
        saltLength = 1;
    } else if (saltLength > 128) {
        saltLength = 128;
    }

    // Make sure the specified time is not zero and fits into a uint32_t.
    
    if (derivationTimeMilliseconds < 1.0) {
        derivationTimeMilliseconds = 1.0;
    } else if (derivationTimeMilliseconds > (double) UINT32_MAX) {
        derivationTimeMilliseconds = (double) UINT32_MAX;
    }
    
    // Do the key derivation.
    
    result = CCCalibratePBKDF(
        kCCPBKDF2, 
        passwordLength, 
        saltLength, 
        kCCPRFHmacAlgSHA1, 
        self.derivedKeyLength, 
        (uint32_t) derivationTimeMilliseconds
    );
    
    // CCCalibratePBKDF returns undocumented error codes <rdar://problem/13641039>.
    
    if ( (result == (unsigned int) -1) || (result == (unsigned int) -2) ) {
        // Setting actualRounds to 0 triggers an error path in our caller.
        result = 0;
    }
    
    // Save the result.  This can't truncate because NSUInteger always has either the same 
    // or more range than (unsigned int).
    
    self.actualRounds = result;
}

- (void)main
{
    CCCryptorStatus         err;
    const char *            passwordUTF8;
    size_t                  passwordUTFLength;
    const uint8_t *         saltPtr;
    static const uint8_t    saltDummy = 0;
    size_t                  saltLength;
    NSMutableData *         result;

    result = [[NSMutableData alloc] initWithLength:self.derivedKeyLength];

    passwordUTF8 = [self.passwordString UTF8String];
    passwordUTFLength = strlen(passwordUTF8);

    // If the salt is zero bytes long then saltPtr ends up being NULL.  This causes 
    // CCKeyDerivationPBKDF to fail with an error.  We fix this by passing in a 
    // pointer a dummy variable in that case.
    
    saltLength = [self.saltData length];
    if (saltLength == 0) {
        saltPtr = &saltDummy;
    } else {
        saltPtr = [self.saltData bytes];
    }

    // If the client didn't specify the rounds, calculate one based on the derivation time.
    
    if (self.rounds != 0) {
        self.actualRounds = self.rounds;
    } else {
        // Note that we only pass in the values that we've already calculated; the method reads 
        // various other properties.
        [self calculateActualRoundsForPasswordLength:passwordUTFLength saltLength:saltLength];
    }
    
    // Check that actualRounds makes sense.
    
    err = kCCSuccess;
    if (self.actualRounds == 0) {
        err = kCCParamError;
    } else if (self.actualRounds > UINT_MAX) {
        err = kCCParamError;
    }
    
    // Do the key derivation and save the results.
    
    if (err == kCCSuccess) {
        err = CCKeyDerivationPBKDF(
            kCCPBKDF2, 
            passwordUTF8, passwordUTFLength, 
            saltPtr, saltLength, 
            kCCPRFHmacAlgSHA1, 
            (unsigned int) self.actualRounds,
            [result mutableBytes], 
            [result length]
        );
        if (err == -1) {
            // The header docs say that CCKeyDerivationPBKDF returns kCCParamError but that's not the case 
            // on current systems; you get -1 instead <rdar://problem/13640477>.  We translate -1, which isn't 
            // a reasonable CommonCrypto error, to kCCParamError.
            err = kCCParamError;
        }
    }
    if (err == kCCSuccess) {
        self.derivedKeyData = result;
    } else {
        self.error = [NSError errorWithDomain:kQCCPBKDF2KeyDerivationErrorDomain code:err userInfo:nil];
    }
}

@end

NSString * kQCCPBKDF2KeyDerivationErrorDomain = @"kQCCPBKDF2KeyDerivationErrorDomain";
