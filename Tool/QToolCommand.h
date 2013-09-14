/*
     File: QToolCommand.h
 Abstract: Command line tool infrastructure.
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

// IMPORTANT: This module is based on <x-man-page://3/getopt> and, as such, is only 
// safe to use from the main thread.

@interface QToolCommand : NSObject

// This class implements a single command line tool command.  You can use it directly 
// for a simple command or via the QComplexToolCommand subclass for commands with 
// subcommands.  This class is an abstract class that you can subclass to implement 
// command-specific behaviour.

// the following must be overridden

+ (NSString *)commandName;
    // Returns the name of the command for various purposes.
    // 
    // The default implementation throws.
    
+ (NSString *)commandUsage;
    // Returns the command's usage.
    //
    // The default implementation throws.

- (BOOL)runError:(NSError **)errorPtr;
    // Runs the command.  Return NO to indicate an error running the 
    // command (and set *errorPtr, if it's not NULL, to the error).
    // 
    // IMPORTANT: Do not do usage checking here.  Instead you should do that 
    // in -validateOptionsAndArguments:.
    // 
    // The default implementation throws.

// the following may be overridden

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments;
    // Validates the commands options and arguments.  Returning NO here 
    // will trigger a usage error.
    // 
    // The default implementation a) parses options as per the methods below, and b) 
    // saves the remaining arguments to .arguments.  It may be overridden to do special 
    // processing, for example, to check the argument count, handle inter-option 
    // dependencies, or process subcommands.

@property (nonatomic, copy,   readonly ) NSArray *  arguments;

// the following may be implementation to support per-command options

- (NSString *)commandOptions;
    // Return a getopt-compatible options string.
    // 
    // The default implementation return the empty string.
    // 
    // For each option you support you must allow the option to be set by 
    // overriding one of the following methods (or implementing the methods 
    // that they dynamic dispatch to).

- (void)setOption:(int)option;
    // Sets the specified option.
    //
    // The default implementation looks for method -setOption_X (where X is the option character) 
    // and calls that if it's available.  If that method isn't present, this method throws.

- (BOOL)setOption:(int)option argument:(NSString *)argument;
    // Sets the specified option.  Return NO to trigger a usage error.
    //
    // The default implementation looks for method -setOption_X_argument: 
    // (where X is the option character) and calls that.  If that method isn't 
    // present, this method throws.

// utilities

+ (NSArray *)optionsAndArgumentsFromArgC:(int)argc argV:(char **)argv;
    // Returns an options and arguments array from the classic UNIX argc/argv pair. 
    // This basically involves converting each element of the array to an NSString and 
    // building these strings into an array.
    //
    // WARNING: This will return nil if any item in the array isn't valid UTF-8.
    //
    // IMPORTANT: The first item of the array is ignored, as is standard for UNIX tools.

@end

@interface QComplexToolCommand : QToolCommand

// This class implements a command that is made up of subcommands.  Like QToolCommand it 
// is intended to be subclassed, with 

+ (NSArray *)subcommandClasses;
    // Returns the classes of the various subcommands implemented by this command.
    //
    // The ddefault implementation throws.

+ (NSString *)commandUsage;
    // This override returns the usage of each of the subcommands, separated by "\n".

@end
