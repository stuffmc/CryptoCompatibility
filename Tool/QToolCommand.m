/*
     File: QToolCommand.m
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

#import "QToolCommand.h"

#include <objc/message.h>

#include <getopt.h>

@interface QToolCommand ()

@property (nonatomic, copy,   readwrite) NSArray *  arguments;

@end

@implementation QToolCommand

+ (NSString *)commandName
{
    NSAssert(NO, @"implementation required");
    return nil;
}
    
+ (NSString *)commandUsage
{
    NSAssert(NO, @"implementation required");
    return nil;
}

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments
{
    BOOL            success;
    NSUInteger      argc;
    const char **   argv;
    const char *    commandOptionsCStr;
    int             opt;
    
    optind = 0;
    optreset = 1;
    
    // Create argc and argv to mirror our arguments.
    
    argc = [optionsAndArguments count];
    argv = malloc(argc * sizeof(const char *));
    for (NSUInteger argIndex = 0; argIndex < argc; argIndex++) {
        argv[argIndex] = [optionsAndArguments[argIndex] UTF8String];
    }
    
    success = YES;
    commandOptionsCStr = [[self commandOptions] UTF8String];
    do {
        // I'm casting away a const here, which is a bit of a worry.  If getopt 
        // modified the string, I'd be in trouble.  AFAIK this doesn't happen.
        opt = getopt( (int) argc, (char **) argv, commandOptionsCStr);
        if (opt != -1) {
            success = (opt != '?');     // getopt passes us '?' for unrecognised options, but we don't want to pass that to -setOption:[argument:]
            if (success) {
                if (optarg == NULL) {
                    [self setOption:opt];
                } else {
                    NSString *  optargStr;
                    
                    optargStr = [[NSString alloc] initWithUTF8String:optarg];
                    if (optargStr == nil) {
                        success = NO;   // not valid UTF-8
                    } else {
                        success = [self setOption:opt argument:optargStr];
                    }
                }
            }
        }
    } while ( (opt != -1) && success );
    
    // Save away the remaining arguments.
    
    if (success) {
        assert(optind >= 0);
        assert( (NSUInteger) optind <= argc);
        self.arguments = [optionsAndArguments subarrayWithRange:NSMakeRange(optind, argc - optind)];
    }
    
    // Clean up.
    
    free(argv);
    
    return success;
}

+ (NSArray *)optionsAndArgumentsFromArgC:(int)argc argV:(char **)argv
{
    NSMutableArray *    optionsAndArguments;
    
    optionsAndArguments = [[NSMutableArray alloc] init];
    
    for (int argIndex = 1; argIndex < argc; argIndex++) {
        NSString *  argStr;
        
        argStr = [[NSString alloc] initWithUTF8String:argv[argIndex]];
        if (argStr != nil) {
            [optionsAndArguments addObject:argStr];
        } else {
            optionsAndArguments = nil;
            break;
        }
    }
    return optionsAndArguments;
}

- (BOOL)runError:(NSError **)errorPtr
{
    #pragma unused(errorPtr)
    NSAssert(NO, @"implementation required");
    return NO;
}

- (NSString *)commandOptions
{
    return @"";
}

static BOOL IsValidOption(int option)
{
    return ((option >= 'a') && (option <= 'z')) || ((option >= 'A') && (option <= 'Z')) || ((option >= '0') && (option <= '9')) || (option == '_');
}

- (void)setOption:(int)option
{
    BOOL        success;
    SEL         sel;
    typedef void (*SetOptionFunc)(id self, SEL sel);
    
    success = IsValidOption(option);
    if (success) {
        sel = NSSelectorFromString([NSString stringWithFormat:@"setOption_%c", option]);
        success = [self respondsToSelector:sel];
    }
    if (success) {
        (void) ((SetOptionFunc) objc_msgSend)(self, sel);
    }
    NSAssert(success, @"-setOption_X method not found");
}

- (BOOL)setOption:(int)option argument:(NSString *)argument;
{
    BOOL        success;
    SEL         sel;
    typedef BOOL (*SetOptionArgumentFunc)(id self, SEL sel, NSString * argument);
    
    success = IsValidOption(option);
    if (success) {
        sel = NSSelectorFromString([NSString stringWithFormat:@"setOption_%c_argument:", option]);
        success = [self respondsToSelector:sel];
    }
    if (success) {
        success = ((SetOptionArgumentFunc) objc_msgSend)(self, sel, argument);
    } else {
        NSAssert(NO, @"-setOption_X_argument: method not found");
    }
    return success;
}

@end

@interface QComplexToolCommand ()

@property (nonatomic, strong, readwrite) QToolCommand *     subcommand;

@end

@implementation QComplexToolCommand

+ (NSArray *)subcommandClasses
{
    NSAssert(NO, @"implementation required");
    return nil;
}

+ (NSString *)commandUsage
{
    NSMutableArray *    result;
    
    result = [[NSMutableArray alloc] init];
    for (Class subcommandClass in [self subcommandClasses]) {
        [result addObject:[subcommandClass commandUsage]];
    }
    return [result componentsJoinedByString:@"\n"];;
}

- (BOOL)validateOptionsAndArguments:(NSArray *)optionsAndArguments
{
    BOOL        success;
    NSString *  subcommandName;
    NSArray *   subcommandArguments;
    
    success = [super validateOptionsAndArguments:optionsAndArguments];
    if (success) {
        success = ([self.arguments count] != 0);         // must have enough for a subcommand
    }
    if (success) {
        subcommandName = [self.arguments objectAtIndex:0];
        subcommandArguments = [self.arguments subarrayWithRange:NSMakeRange(1, [self.arguments count] - 1)];
        
        for (Class subcommandClass in [[self class] subcommandClasses]) {
            if ( [subcommandName isEqual:[subcommandClass commandName]] ) {
                self.subcommand = [[subcommandClass alloc] init];
                break;
            }
        }
        success = (self.subcommand != nil);
    }
    if (success) {
        success = [self.subcommand validateOptionsAndArguments:subcommandArguments];
    }
    
    return success;
}

- (BOOL)runError:(NSError **)errorPtr
{
    assert(self.subcommand != nil);
    return [self.subcommand runError:errorPtr];
}

@end
