/*
     File: QCCRSASmallCryptor.m
 Abstract: Implements RSA encryption and decryption (using SecKeyRaw API).
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

#import "QCCRSASmallCryptor.h"

#import <Security/Security.h>

@interface QCCRSASmallCryptor ()

enum QCCRSASmallCryptorOperation {
    kQCCRSASmallCryptorOperationEncrypt, 
    kQCCRSASmallCryptorOperationDecrypt
};
typedef enum QCCRSASmallCryptorOperation QCCRSASmallCryptorOperation;

@property (atomic, assign, readonly ) QCCRSASmallCryptorOperation   op;

// read/write versions of public properties

@property (atomic, copy,   readwrite) NSError *     error;
@property (atomic, copy,   readwrite) NSData *      smallOutputData;

@end

@implementation QCCRSASmallCryptor

- (id)initWithOperation:(QCCRSASmallCryptorOperation)op smallInputData:(NSData *)smallInputData key:(SecKeyRef)key
{
    NSParameterAssert(smallInputData != nil);
    NSParameterAssert(key != NULL);
    self = [super init];
    if (self != nil) {
        self->_op = op;
        self->_smallInputData = [smallInputData copy];
        CFRetain(key);
        self->_key = key;
        self->_padding = kQCCRSASmallCryptorPaddingPKCS1;
    }
    return self;
}

- (id)initToEncryptSmallInputData:(NSData *)smallInputData key:(SecKeyRef)key
{
    return [self initWithOperation:kQCCRSASmallCryptorOperationEncrypt smallInputData:smallInputData key:key];
}

- (id)initToDecryptSmallInputData:(NSData *)smallInputData key:(SecKeyRef)key
{
    return [self initWithOperation:kQCCRSASmallCryptorOperationDecrypt smallInputData:smallInputData key:key];
}

- (void)dealloc
{
    CFRelease(self->_key);
}

- (void)mainAfterParameterChecks
{
    OSStatus            err;
    SecPadding          padding;
    NSMutableData *     resultData;
    size_t              resultDataLength;

    // Map our padding constant appropriately.
        
    switch (self.padding) {
        case kQCCRSASmallCryptorPaddingNone: {
            padding = kSecPaddingNone;
        } break;
        default:
            assert(NO);
            // fall through
        case kQCCRSASmallCryptorPaddingPKCS1: {
            padding = kSecPaddingPKCS1;
        } break;
    }
    
    // Do the crypto.
        
    resultData = [[NSMutableData alloc] initWithLength:SecKeyGetBlockSize(self.key)];
    resultDataLength = [resultData length];
    switch (self.op) {
        default:
            assert(NO);
            // fall through
        case kQCCRSASmallCryptorOperationEncrypt: {
            err = SecKeyEncrypt(
                self.key, 
                padding, 
                [self.smallInputData bytes], [self.smallInputData length], 
                [resultData mutableBytes], &resultDataLength
            );
        } break;
        case kQCCRSASmallCryptorOperationDecrypt: {
            err = SecKeyDecrypt(
                self.key, 
                padding, 
                [self.smallInputData bytes], [self.smallInputData length], 
                [resultData mutableBytes], &resultDataLength
            );
        } break;
    }
    
    // Set up the result.
    
    if (err == errSecSuccess) {
        // Set the output length to the value returned by the crypto.  This is necessary because, 
        // in the decrypt case, the padding means we have allocated more space that we need.
        [resultData setLength:resultDataLength];
        self.smallOutputData = resultData;
    } else {
        self.error = [NSError errorWithDomain:NSOSStatusErrorDomain code:err userInfo:nil];
    }    
}

- (void)main
{
    OSStatus                err;
    NSUInteger              smallInputDataLength;
    NSUInteger              keyBlockSize;
    
    smallInputDataLength = [self.smallInputData length];
    keyBlockSize = SecKeyGetBlockSize(self.key);

    // Check that the input data length makes sense.
    
    err = errSecSuccess;
    switch (self.op) {
        default:
            assert(NO);
            // fall through
        case kQCCRSASmallCryptorOperationEncrypt: {
            switch (self.padding) {
                case kQCCRSASmallCryptorPaddingNone: {
                    if (smallInputDataLength != keyBlockSize) {
                        err = errSecParam;
                    }
                } break;
                default:
                    assert(NO);
                    // fall through
                case kQCCRSASmallCryptorPaddingPKCS1: {
                    assert(keyBlockSize > 11);
                    if ((smallInputDataLength + 11) > keyBlockSize) {
                        err = errSecParam;
                    }
                } break;
            }
        } break;
        case kQCCRSASmallCryptorOperationDecrypt: {
            if (smallInputDataLength != keyBlockSize) {
                err = errSecParam;
            }
        } break;
    }

    // If everything is OK, call the real code.
    
    if (err != errSecSuccess) {
        self.error = [NSError errorWithDomain:NSOSStatusErrorDomain code:errSecParam userInfo:nil];
    } else {
        [self mainAfterParameterChecks];
    }
}

@end
