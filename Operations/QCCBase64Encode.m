/*
     File: QCCBase64Encode.m
 Abstract: Implements Base64 encoding.
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

#import "QCCBase64Encode.h"

#import <resolv.h>

@interface QCCBase64Encode ()

// read/write versions of public properties

@property (atomic, copy,   readwrite) NSString *    outputString;

@end

@implementation QCCBase64Encode

- (id)initWithInputData:(NSData *)inputData
{
    NSParameterAssert(inputData != nil);
    self = [super init];
    if (self != nil) {
        self->_inputData = [inputData copy];
    }
    return self;
}

- (void)main
{
    NSString *      result;
    int             bytesEncoded;
    NSMutableData * stringData;

    // int b64_ntop(uint8_t const * source, size_t sourceLength, char * target, size_t targetSize);
    //
    // source and sourceLength denote the data to be encoded.
    //
    // target and targetSize denote the buffer for the encoded data.  The buffer 
    // must be big enough to allow for all the Base64 bytes and a trailing null. 
    // The value (((sourceLength + 2) / 3) * 4) + 1 should be correct.
    // 
    // returns -1 on error or the number of Base64 bytes (not including the trailing 
    // null) placed in the target buffer.  The only error is the target buffer being 
    // too small.
    
    result = nil;
    
    stringData = [NSMutableData dataWithLength:((([self.inputData length] + 2) / 3) * 4) + 1];
    
    bytesEncoded = b64_ntop([self.inputData bytes], [self.inputData length], [stringData mutableBytes], [stringData length]);
    if (bytesEncoded >= 0) {
        assert( (((NSUInteger) bytesEncoded) + 1) == [stringData length]);
        result = [[NSString alloc] initWithUTF8String:[stringData bytes]];
    }
    assert(result != nil);

    if (self.addLineBreaks) {
        NSMutableString *   resultWithLineBreaks;
        NSUInteger          cursor;
        NSUInteger          limit;
        
        resultWithLineBreaks = [[NSMutableString alloc] init];
        cursor = 0;
        limit = [result length];
        while (cursor < limit) {
            NSUInteger      charsThisTime;
            
            if ( (limit - cursor) > 64 ) {
                charsThisTime = 64;
            } else {
                charsThisTime = (limit - cursor);
            }
            [resultWithLineBreaks appendFormat:@"%@\n", [result substringWithRange:NSMakeRange(cursor, charsThisTime)]];
            cursor += charsThisTime;
        }
        self.outputString = resultWithLineBreaks;
    } else {
        self.outputString = result;
    }
}

@end
