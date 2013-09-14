/*
     File: QCCAESCryptor.m
 Abstract: Implements AES encryption and decryption without padding.
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

#import "QCCAESCryptor.h"

#include <CommonCrypto/CommonCrypto.h>

@interface QCCAESCryptor ()

@property (atomic, assign, readonly ) CCOperation   op;

// read/write versions of public properties

@property (atomic, copy,   readwrite) NSError *     error;
@property (atomic, copy,   readwrite) NSData *      outputData;

@end

@implementation QCCAESCryptor

- (id)initWithOp:(CCOperation)op inputData:(NSData *)inputData keyData:(NSData *)keyData
{
    NSParameterAssert(inputData != nil);
    NSParameterAssert(keyData != nil);
    self = [super init];
    if (self != nil) {
        self->_op = op;
        self->_inputData = [inputData copy];
        self->_keyData = [keyData copy];
        self->_ivData = [[NSMutableData alloc] initWithLength:kCCBlockSizeAES128];
    }
    return self;
}

- (id)initToEncryptInputData:(NSData *)inputData keyData:(NSData *)keyData
{
    return [self initWithOp:kCCEncrypt inputData:inputData keyData:keyData];
}

- (id)initToDecryptInputData:(NSData *)inputData keyData:(NSData *)keyData
{
    return [self initWithOp:kCCDecrypt inputData:inputData keyData:keyData];
}

- (void)main
{
    CCCryptorStatus     err;
    NSUInteger          keyDataLength;
    NSMutableData *     result;
    size_t              resultLength;
    
    // We check for common input problems to make it easier for someone tracing through 
    // the code to find problems (rather than just getting a mysterious kCCParamError back 
    // from CCCrypt).
    
    err = kCCSuccess;
    if (([self.inputData length] % kCCBlockSizeAES128) != 0) {
        err = kCCParamError;
    }
    keyDataLength = [self.keyData length];
    if ( (keyDataLength != kCCKeySizeAES128) && (keyDataLength != kCCKeySizeAES192) && (keyDataLength != kCCKeySizeAES256) ) {
        err = kCCParamError;
    }
    if ( (self.ivData != nil) && ([self.ivData length] != kCCBlockSizeAES128) ) {
        err = kCCParamError;
    }
    
    if (err == kCCSuccess) {
        result = [[NSMutableData alloc] initWithLength:[self.inputData length]];

        err = CCCrypt(
            self.op, 
            kCCAlgorithmAES128, 
            (self.ivData == nil) ? kCCOptionECBMode : 0, 
            [self.keyData bytes],   [self.keyData length], 
            [self.ivData bytes],                                // will be NULL if ivData is nil
            [self.inputData bytes], [self.inputData length], 
            [result mutableBytes],  [result length], 
            &resultLength
        );
    }
    if (err == kCCSuccess) {
        // In the absence of padding the data out is always the same size as the data in.
        assert(resultLength == [result length]);
        self.outputData = result;
    } else {
        self.error = [NSError errorWithDomain:kQCCAESCryptorErrorDomain code:err userInfo:nil];
    }
}

@end

NSString * kQCCAESCryptorErrorDomain = @"kQCCAESCryptorErrorDomain";
