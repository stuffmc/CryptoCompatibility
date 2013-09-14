/*
     File: QCCAESPadBigCryptor.m
 Abstract: Implements AES encryption and decryption with PKCS#7 padding in a way that's suitable for large data sets.
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

#import "QCCAESPadBigCryptor.h"

#include <CommonCrypto/CommonCrypto.h>

@interface QCCAESPadBigCryptor ()

@property (atomic, assign, readonly ) CCOperation       op;
@property (atomic, assign, readwrite) BOOL              didOpenInputStream;
@property (atomic, assign, readwrite) BOOL              didOpenOutputStream;

// read/write versions of public properties

@property (atomic, copy,   readwrite) NSError *         error;
@property (atomic, strong, readwrite) NSOutputStream *  outputStream;

@end

@implementation QCCAESPadBigCryptor

- (id)initWithOp:(CCOperation)op inputStream:(NSInputStream *)inputStream outputStream:(NSOutputStream *)outputStream keyData:(NSData *)keyData
{
    NSParameterAssert(inputStream != nil);
    NSParameterAssert(outputStream != nil);
    NSParameterAssert(keyData != nil);
    self = [super init];
    if (self != nil) {
        self->_op = op;
        self->_inputStream = inputStream;
        self->_outputStream = outputStream;
        self->_keyData = [keyData copy];
        self->_ivData = [[NSMutableData alloc] initWithLength:kCCBlockSizeAES128];
    }
    return self;
}

- (id)initToEncryptInputStream:(NSInputStream *)inputStream toOutputStream:(NSOutputStream *)outputStream keyData:(NSData *)keyData
{
    return [self initWithOp:kCCEncrypt inputStream:inputStream outputStream:outputStream keyData:keyData];
}

- (id)initToDecryptInputStream:(NSInputStream *)inputStream toOutputStream:(NSOutputStream *)outputStream keyData:(NSData *)keyData
{
    return [self initWithOp:kCCDecrypt inputStream:inputStream outputStream:outputStream keyData:keyData];
}

- (void)readToInputBuffer:(NSMutableData *)inputBuffer
    // Read bytes from the input stream into the input buffer, setting self.error if something 
    // goes wrong.
    // 
    // Note that -read:maxLength: might not return the full number of bytes we request, either 
    // because it's hit the end of file or because it's having a bad day.  That's OK, we can 
    // handle a non-full input buffer.
    //
    // Also note that this does fail if we hit the end of the input stream; rather it returns 
    // an empty input buffer.
{
    NSInteger       bytesRead;

    if (self.error == nil) {
        bytesRead = [self.inputStream read:[inputBuffer mutableBytes] maxLength:[inputBuffer length]];
        if (bytesRead >= 0) {
            [inputBuffer setLength: (NSUInteger) bytesRead];
        } else {
            self.error = [self.inputStream streamError];
            assert(self.error != nil);  // error on input stream
        }
    }
}

- (void)writeFromOutputBuffer:(NSMutableData *)outputBuffer
    // Write bytes from the output buffer to the output stream, setting self.error if something 
    // goes wrong.
    //
    // Note that this does nothing if a) self.error is set, implying that we got an error 
    // somewhere 'upstream', or b) the output buffer length is zero.
    //
    // IMPORTANT: -write:maxLength: might not write all the bytes we give it, so we have to loop 
    // until we've written everything.
{
    NSUInteger      bytesTotal;
    NSUInteger      bytesSoFar;
    const uint8_t * buffer;
    NSInteger       bytesWritten;
    
    bytesSoFar = 0;
    bytesTotal = [outputBuffer length];
    buffer = (const uint8_t *) [outputBuffer bytes];
    while ( (self.error == nil) && (bytesSoFar != bytesTotal) ) {
        bytesWritten = [self.outputStream write:&buffer[bytesSoFar] maxLength:bytesTotal - bytesSoFar];
        if (bytesWritten < 0) {
            self.error = [self.outputStream streamError];
        } else if (bytesWritten == 0) {
            self.error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EPIPE userInfo:nil];
        } else {
            bytesSoFar += (NSUInteger) bytesWritten;
        }
    }
}

- (BOOL)processChunkWithCryptor:(CCCryptorRef)cryptor inputBuffer:(NSMutableData *)inputBuffer outputBuffer:(NSMutableData *)outputBuffer
    // Read a chunk of data from the input stream into the input buffer, run it through 
    // the cryptor into the output buffer, and then write it to the output stream.  
    // If something goes wrong, set self.error.  Return YES if we're all done (either 
    // because we read the last chunk from the input stream or because we got an error).
{
    CCCryptorStatus     err;
    size_t              bytesToWrite;

    if (self.isCancelled) {
        self.error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSUserCancelledError userInfo:nil];
    }

    // Read the next chunk of data from the input stream.
    //
    // Note that this does nothing if self.error is set.
    
    [self readToInputBuffer:inputBuffer];
    
    // Crypt it.
    // 
    // Note that if we hit the end of the input stream than the input buffer will 
    // have a length of zero, meaning we should call CCCryptorUpdate to get any 
    // bytes that are left over in the cryptor.
    
    if (self.error == nil) {
        if ([inputBuffer length] != 0) {
            err = CCCryptorUpdate(
                cryptor, 
                [inputBuffer bytes], [inputBuffer length], 
                [outputBuffer mutableBytes], [outputBuffer length], 
                &bytesToWrite
            );
        } else {
            err = CCCryptorFinal(
                cryptor, 
                [outputBuffer mutableBytes], [outputBuffer length], 
                &bytesToWrite
            );
        }
        if (err == kCCSuccess) {
            [outputBuffer setLength:bytesToWrite];
        } else {
            self.error = [NSError errorWithDomain:kQCCAESPadBigCryptorErrorDomain code:err userInfo:nil];
        }
    }
    
    // Write it out to the output stream.
    //
    // Note that this does nothing if self.error is set.
    
    [self writeFromOutputBuffer:outputBuffer];
    
    return (self.error != nil) || ([inputBuffer length] == 0);
}

- (void)processStreamsInputBuffer:(NSMutableData *)inputBuffer outputBuffer:(NSMutableData *)outputBuffer
    // Processes the input stream and write the results to the input stream, using the input and output 
    // buffers as scratch space.  Set self.error if there's a problem.
{
    CCCryptorStatus     err;
    CCCryptorStatus     junk;
    CCCryptorRef        cryptor;
    
    cryptor = NULL;
    
    // Create the cryptor.
    
    err = CCCryptorCreate(
        self.op, 
        kCCAlgorithmAES128, 
        ((self.ivData == nil) ? kCCOptionECBMode : 0) | kCCOptionPKCS7Padding, 
        [self.keyData bytes], [self.keyData length], 
        [self.ivData bytes],                                // will be NULL if ivData is nil
        &cryptor
    );
    if (err != kCCSuccess) {
        self.error = [NSError errorWithDomain:kQCCAESPadBigCryptorErrorDomain code:err userInfo:nil];
    }
    
    // Process the input, one chunk at a time.
    
    if (self.error == nil) {
        BOOL                done;
        NSUInteger          initialInputBufferLength;
        NSUInteger          initialOutputBufferLength;

        initialInputBufferLength  = [inputBuffer  length];
        initialOutputBufferLength = [outputBuffer length];

        do {
            [inputBuffer  setLength:initialInputBufferLength ];
            [outputBuffer setLength:initialOutputBufferLength];

            done = [self processChunkWithCryptor:cryptor inputBuffer:inputBuffer outputBuffer:outputBuffer];
        } while ( ! done );
    }
    
    // Clean up.
    
    if (cryptor != NULL) {
        junk = CCCryptorRelease(cryptor);
        assert(junk == kCCSuccess);
    }
}

- (void)mainAfterParameterChecks
{
    NSUInteger          padLength;
    NSMutableData *     inputBuffer;
    NSMutableData *     outputBuffer;
    
    // Open the streams if necessary.

    if ([self.inputStream streamStatus] == NSStreamStatusNotOpen) {
        [self.inputStream open];
        self.didOpenInputStream = YES;
    }
    if ([self.outputStream streamStatus] == NSStreamStatusNotOpen) {
        [self.outputStream open];
        self.didOpenOutputStream = YES;
    }
    
    // Allocate the input and output buffers.  We use a 64K buffer, which is generally a good 
    // size when reading from a file.
    //
    // Padding can expand the data, so we have to allocate space for that.  The rule for block 
    // cyphers, like AES, is that the padding only adds space on encryption (on decryption it 
    // can reduce space, obviously, but we don't need to account for that) and it will only add 
    // at most one block size worth of space.

    if (self.op == kCCEncrypt) {
        padLength = kCCBlockSizeAES128;
    } else {
        padLength = 0;
    }
    inputBuffer  = [[NSMutableData alloc] initWithLength:64 * 1024];
    outputBuffer = [[NSMutableData alloc] initWithLength:[inputBuffer length] + padLength];

    // Run the cryptor.
    
    [self processStreamsInputBuffer:inputBuffer outputBuffer:outputBuffer];
    
    // Close any streams we opened.
    
    if (self.didOpenInputStream) {
        [self.inputStream close];
    }
    if (self.didOpenOutputStream) {
        [self.outputStream close];
    }
}

- (void)main
{
    CCCryptorStatus     err;
    NSUInteger          keyDataLength;

    // We check for common input problems to make it easier for someone tracing through 
    // the code to find problems (rather than just getting a mysterious kCCParamError back 
    // from CCCrypt).

    err = kCCSuccess;
    keyDataLength = [self.keyData length];
    if ( (keyDataLength != kCCKeySizeAES128) && (keyDataLength != kCCKeySizeAES192) && (keyDataLength != kCCKeySizeAES256) ) {
        err = kCCParamError;
    }
    if ( (self.ivData != nil) && ([self.ivData length] != kCCBlockSizeAES128) ) {
        err = kCCParamError;
    }
    if (err != kCCSuccess) {
        self.error = [NSError errorWithDomain:kQCCAESPadBigCryptorErrorDomain code:err userInfo:nil];
    } else {
        [self mainAfterParameterChecks];
    }
}

@end

NSString * kQCCAESPadBigCryptorErrorDomain = @"kQCCAESPadBigCryptorErrorDomain";
