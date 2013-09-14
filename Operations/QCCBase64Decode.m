/*
     File: QCCBase64Decode.m
 Abstract: Implements Base64 decoding.
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

#import "QCCBase64Decode.h"

#include <resolv.h>

@interface QCCBase64Decode ()

// read/write versions of public properties

@property (atomic, copy,   readwrite) NSData *      outputData;

@end

@implementation QCCBase64Decode

- (id)initWithInputString:(NSString *)inputString
{
    NSParameterAssert(inputString != nil);
    self = [super init];
    if (self != nil) {
        self->_inputString = [inputString copy];
    }
    return self;
}

- (void)main
{
    NSMutableData * result;
    const char *    stringC;
    size_t          stringCLength;
    int             bytesDecoded;
    
    // int b64_pton(char const * source, uint8_t * target, size_t targetSize);
    //
    // source is a C string containing the Base64 data.
    //
    // target is a buffer; it can be NULL, in which case targetSize is ignored 
    // and the function just returns the number of bytes that would have been 
    // decoded.
    // 
    // targetSize is the size of the buffer pointed to by target (if any).
    //
    // returns -1 on error or the number of bytes decoded otherwise.  Common errors 
    // include an invalid character and the target buffer being too small.

    stringC = [self.inputString UTF8String];
    stringCLength = strlen(stringC);
    
    // We can never get more than 3 bytes of data for every 4 bytes of input we have. 
    // It could actually be substantially less (for example, if the parser skips a 
    // bunch of whitespace) but this is a valid upper bound.
    
    result = [NSMutableData dataWithLength:((stringCLength + 3) / 4) * 3];
    bytesDecoded = b64_pton(stringC, [result mutableBytes], [result length]);
    if (bytesDecoded < 0) {
        result = nil;
    } else {
        [result setLength: (NSUInteger) bytesDecoded];
    }

    self.outputData = result;
}

@end
