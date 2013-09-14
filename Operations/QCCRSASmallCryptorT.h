/*
     File: QCCRSASmallCryptorT.h
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

#import <Foundation/Foundation.h>

// IMPORTANT: This is for encrypting and decrypting small amounts of data, not an 
// entire file.  The standard technique for encrypting a large file is to 
// encrypt it with a symmetric algorithm (AES-128) using a randomly generated 
// key and then encrypt that key with RSA.  However, doing that sort of thing 
// correctly is a challenge and we recommend you use some standard encryption 
// scheme (such as CMS).
// 
// The exact definition of small depends on the key size and the padding in 
// use.  For example, a 2048-bit key with PKCS#1 padding can encrypt 245 bytes 
// (2048 bits -> 256 bytes - 11).  Don't ask me why or I'll start to whimper (-:

@interface QCCRSASmallCryptorT : NSOperation

- (id)initToEncryptSmallInputData:(NSData *)smallInputData key:(SecKeyRef)key;      // must be the *private* key
- (id)initToDecryptSmallInputData:(NSData *)smallInputData key:(SecKeyRef)key;      // must be the *public*  key

// properties set by the init method

@property (atomic, copy,   readonly ) NSData *      smallInputData;
@property (atomic, assign, readonly ) SecKeyRef     key;

// properties that may be set before running

// IMPORTANT: kQCCRSASmallCryptorTPaddingNone requires OS X 10.8 or later due to 
// limitations of the underlying security transform <rdar://problem/9987765>.

enum QCCRSASmallCryptorTPadding {
    kQCCRSASmallCryptorTPaddingNone,
    kQCCRSASmallCryptorTPaddingPKCS1                                    // the default
};
typedef enum QCCRSASmallCryptorTPadding QCCRSASmallCryptorTPadding;

@property (atomic, assign, readwrite) QCCRSASmallCryptorTPadding padding;

// properties set on finish

@property (atomic, copy,   readonly ) NSError *     error;     
@property (atomic, copy,   readonly ) NSData *      smallOutputData;    // on successful encrypt, length match the key size (that is, for a 2048-bit key this will be 256 bytes)
                                                                        // on successful decrypt, length can be any value
@end
