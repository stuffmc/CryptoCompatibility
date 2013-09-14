/*
     File: QCCRSASHA1VerifyT.m
 Abstract: Implements RSA SHA1 signature verification (using SecTransform API).
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

#import "QCCRSASHA1VerifyT.h"

@interface QCCRSASHA1VerifyT ()

// read/write versions of public properties

@property (atomic, copy,   readwrite) NSError *     error;
@property (atomic, assign, readwrite) BOOL          verified;

@end

@implementation QCCRSASHA1VerifyT

- (id)initWithInputData:(NSData *)inputData publicKey:(SecKeyRef)publicKey signatureData:(NSData *)signatureData
{
    NSParameterAssert(inputData != nil);
    NSParameterAssert(publicKey != NULL);
    NSParameterAssert(signatureData != nil);
    self = [super init];
    if (self != nil) {
        self->_inputData = [inputData copy];
        CFRetain(publicKey);
        self->_publicKey = publicKey;
        self->_signatureData = [signatureData copy];
    }
    return self;
}

- (void)dealloc
{
    CFRelease(self->_publicKey);
}

- (void)main
{
    BOOL                success;
    SecTransformRef     transform;
    CFBooleanRef        result;
    CFErrorRef          errorCF;
    
    result = NULL;
    errorCF = NULL;
    
    // Set up the transform.
    
    transform = SecVerifyTransformCreate(self.publicKey, (__bridge CFDataRef) self.signatureData, &errorCF);
    success = (transform != NULL);

    // Note: kSecInputIsAttributeName defaults to kSecInputIsPlainText, which is what we want.

    if (success) {
        success = SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA1, &errorCF) != false;
    }

    if (success) {
        success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, (__bridge CFDataRef) self.inputData, &errorCF) != false;
    }

    // Run it.
    
    if (success) {
        result = SecTransformExecute(transform, &errorCF);
        success = (result != NULL);
    }
    
    // Process the results.
    
    if (success) {
        assert(CFGetTypeID(result) == CFBooleanGetTypeID());
        self.verified = (CFBooleanGetValue(result) != false);
    } else {
        assert(errorCF != NULL);
        self.error = (__bridge NSError *) errorCF;
    }
    
    // Clean up.

    if (result != NULL) {
        CFRelease(result);
    }
    if (errorCF != NULL) {
        CFRelease(errorCF);
    }
    if (transform != NULL) {
        CFRelease(transform);
    }
}

@end
