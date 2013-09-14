/*
     File: QCCRSASHA1Sign.m
 Abstract: Implements RSA SHA1 signing (using SecKeyRaw API).
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

#import "QCCRSASHA1Sign.h"

#include <CommonCrypto/CommonCrypto.h>

@interface QCCRSASHA1Sign ()

// read/write versions of public properties

@property (atomic, copy,   readwrite) NSError *     error;
@property (atomic, copy,   readwrite) NSData *      signatureData;

@end

@implementation QCCRSASHA1Sign

- (id)initWithInputData:(NSData *)inputData privateKey:(SecKeyRef)privateKey;
{
    NSParameterAssert(inputData != nil);
    NSParameterAssert(privateKey != NULL);
    self = [super init];
    if (self != nil) {
        self->_inputData = [inputData copy];
        CFRetain(privateKey);
        self->_privateKey = privateKey;
    }
    return self;
}

- (void)dealloc
{
    CFRelease(self->_privateKey);
}

- (void)main
{
    OSStatus            err;
    uint8_t             digest[CC_SHA1_DIGEST_LENGTH];
    NSMutableData *     resultData;
    size_t              resultDataLength;
    
    // First create a SHA1 digest of the data.
    
    (void) CC_SHA1([self.inputData bytes], (CC_LONG) [self.inputData length], digest);
    
    // Then sign it.
    
    resultData = [[NSMutableData alloc] initWithLength:SecKeyGetBlockSize(self.privateKey)];
    resultDataLength = [resultData length];
    err = SecKeyRawSign(
        self.privateKey, 
        kSecPaddingPKCS1SHA1, 
        digest, 
        sizeof(digest), 
        [resultData mutableBytes], 
        &resultDataLength
    );
    if (err == errSecSuccess) {
        assert(resultDataLength == [resultData length]);
        self.signatureData = resultData;
    } else {
        self.error = [NSError errorWithDomain:NSOSStatusErrorDomain code:err userInfo:nil];
    }
}

@end
