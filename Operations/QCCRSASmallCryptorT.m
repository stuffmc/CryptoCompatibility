/*
     File: QCCRSASmallCryptorT.m
 Abstract: Implements RSA encryption and decryption (using SecTransform API).
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

#import "QCCRSASmallCryptorT.h"

#include <sys/utsname.h>

@interface QCCRSASmallCryptorT ()

enum QCCRSASmallCryptorOperationT {
    kQCCRSASmallCryptorOperationTEncrypt, 
    kQCCRSASmallCryptorOperationTDecrypt
};
typedef enum QCCRSASmallCryptorOperationT QCCRSASmallCryptorOperationT;

@property (atomic, assign, readonly ) QCCRSASmallCryptorOperationT  op;

// read/write versions of public properties

@property (atomic, copy,   readwrite) NSError *     error;
@property (atomic, copy,   readwrite) NSData *      smallOutputData;

@end

@implementation QCCRSASmallCryptorT

- (id)initWithOperation:(QCCRSASmallCryptorOperationT)op smallInputData:(NSData *)smallInputData key:(SecKeyRef)key
{
    NSParameterAssert(smallInputData != nil);
    NSParameterAssert(key != NULL);
    self = [super init];
    if (self != nil) {
        self->_op = op;
        self->_smallInputData = [smallInputData copy];
        CFRetain(key);
        self->_key = key;
        self->_padding = kQCCRSASmallCryptorTPaddingPKCS1;
    }
    return self;
}

- (id)initToEncryptSmallInputData:(NSData *)smallInputData key:(SecKeyRef)key
{
    return [self initWithOperation:kQCCRSASmallCryptorOperationTEncrypt smallInputData:smallInputData key:key];
}

- (id)initToDecryptSmallInputData:(NSData *)smallInputData key:(SecKeyRef)key
{
    return [self initWithOperation:kQCCRSASmallCryptorOperationTDecrypt smallInputData:smallInputData key:key];
}

- (void)dealloc
{
    CFRelease(self->_key);
}

- (void)mainAfterParameterChecks
{
    BOOL                success;
    CFErrorRef          errorCF;
    SecTransformRef     transform;
    CFStringRef         paddingStr;
    CFDataRef           resultData;

    transform = NULL;
    errorCF = NULL;
    resultData = NULL;

    // First determine the padding.
    
    success = YES;
    switch (self.padding) {
        case kQCCRSASmallCryptorTPaddingNone: {
            paddingStr = kSecPaddingNoneKey;
        } break;
        default:
            assert(NO);
            // fall through
        case kQCCRSASmallCryptorTPaddingPKCS1: {
            // For an RSA key the transform does PKCS#1 padding by default.  Weirdly, if we explicitly 
            // set the padding to kSecPaddingPKCS1Key then the transform fails <rdar://problem/13661366>.  
            // Thus, if the client has requested PKCS#1, we leave paddingStr set to NULL, which prevents 
            // us explicitly setting the padding to anything, which avoids the error while giving us 
            // PKCS#1 padding.
            
            // paddingStr = kSecPaddingPKCS1Key;
            paddingStr = NULL;
        } break;
    }
    
    // Now create and execute the transform.
    
    if (success) {
        switch (self.op) {
            default:
                assert(NO);
                // fall through
            case kQCCRSASmallCryptorOperationTEncrypt: {
                transform = SecEncryptTransformCreate(self.key, &errorCF);
            } break;
            case kQCCRSASmallCryptorOperationTDecrypt: {
                transform = SecDecryptTransformCreate(self.key, &errorCF);
            } break;
        }
        success = (transform != NULL);
    }
    if (success && (paddingStr != NULL)) {
        success = SecTransformSetAttribute(transform, kSecPaddingKey, paddingStr, &errorCF) != false;
    }
    if (success) {
        success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, (__bridge CFDataRef) self.smallInputData, &errorCF) != false;
    }
    if (success) {
        resultData = SecTransformExecute(transform, &errorCF);
        success = (resultData != NULL);
    }
    if (success) {
        self.smallOutputData = (__bridge NSData *) resultData;
    } else {
        assert(errorCF != NULL);
        self.error = (__bridge NSError *) errorCF;
    }
    
    if (resultData != NULL) {
        CFRelease(resultData);
    }
    if (errorCF != NULL) {
        CFRelease(errorCF);
    }
    if (transform != NULL) {
        CFRelease(transform);
    }
}

- (void)main
{
    OSStatus                err;
    NSUInteger              smallInputDataLength;
    NSUInteger              keyBlockSize;
    
    smallInputDataLength = [self.smallInputData length];
    keyBlockSize = SecKeyGetBlockSize(self.key);
    
    // Prior to OS X 10.8, SecKeyGetBlockSize returns the key size in bits rather than the 
    // block size <rdar://problem/10623794>.  We can correct this, for RSA keys, which is all 
    // that this operation supports, by simply dividing by 8.
    //
    // Note that the workaround code is designed to fail safely, that is, if some future 
    // changes to uname or atoi cause the string not to be parsed, the workaround will 
    // remain inactive.
    //
    // Also note that 12 is the Darwin major version for 10.8.

    {
        int                 i;
        struct utsname      unameInfo;
        
        i = uname(&unameInfo);
        if (i >= 0) {
            i = atoi(unameInfo.release);
            if ( (i > 0) && (i < 12) ) {
                keyBlockSize = keyBlockSize / 8;
            }
        }
    }

    // Check that the input data length makes sense.
    
    err = errSecSuccess;
    switch (self.op) {
        default:
            assert(NO);
            // fall through
        case kQCCRSASmallCryptorOperationTEncrypt: {
            switch (self.padding) {
                case kQCCRSASmallCryptorTPaddingNone: {
                    if (smallInputDataLength != keyBlockSize) {
                        err = errSecParam;
                    }
                } break;
                default:
                    assert(NO);
                    // fall through
                case kQCCRSASmallCryptorTPaddingPKCS1: {
                    assert(keyBlockSize > 11);
                    if ((smallInputDataLength + 11) > keyBlockSize) {
                        err = errSecParam;
                    }
                } break;
            }
        } break;
        case kQCCRSASmallCryptorOperationTDecrypt: {
            if (smallInputDataLength != keyBlockSize) {
                err = errSecParam;
            }
        } break;
    }
    
    // If everything is OK, call the read code.
    
    if (err != errSecSuccess) {
        self.error = [NSError errorWithDomain:NSOSStatusErrorDomain code:errSecParam userInfo:nil];
    } else {
        [self mainAfterParameterChecks];
    }
}

@end
