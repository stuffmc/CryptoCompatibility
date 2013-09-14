#! /usr/bin/python
#
#     File: ATestAgainstOpenSSL.py
# Abstract: Tests the command line tool against equivalent OpenSSL commands.
#  Version: 1.0
# 
# Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple
# Inc. ("Apple") in consideration of your agreement to the following
# terms, and your use, installation, modification or redistribution of
# this Apple software constitutes acceptance of these terms.  If you do
# not agree with these terms, please do not use, install, modify or
# redistribute this Apple software.
# 
# In consideration of your agreement to abide by the following terms, and
# subject to these terms, Apple grants you a personal, non-exclusive
# license, under Apple's copyrights in this original Apple software (the
# "Apple Software"), to use, reproduce, modify and redistribute the Apple
# Software, with or without modifications, in source and/or binary forms;
# provided that if you redistribute the Apple Software in its entirety and
# without modifications, you must retain this notice and the following
# text and disclaimers in all such redistributions of the Apple Software.
# Neither the name, trademarks, service marks or logos of Apple Inc. may
# be used to endorse or promote products derived from the Apple Software
# without specific prior written permission from Apple.  Except as
# expressly stated in this notice, no other rights or licenses, express or
# implied, are granted by Apple herein, including but not limited to any
# patent rights that may be infringed by your derivative works or by other
# works in which the Apple Software may be incorporated.
# 
# The Apple Software is provided by Apple on an "AS IS" basis.  APPLE
# MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
# THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND
# OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS.
# 
# IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION,
# MODIFICATION AND/OR DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED
# AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING NEGLIGENCE),
# STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# 
# Copyright (C) 2013 Apple Inc. All Rights Reserved.
# 
#

import sys
import os
import subprocess
import tempfile
import time

def pathForResource(relPath):
    return os.path.join(os.path.dirname(sys.argv[0]), "..", "TestData", relPath)

gPathForTool = None

def setupPathForTool():
    global gPathForTool
    if len(sys.argv) == 1:
        gPathForTool = os.path.join(os.path.dirname(sys.argv[0]), "..", "build", "Debug", "CryptoCompatibility")
    else:
        gPathForTool = sys.argv[1]
    
def pathForTool():
    return gPathForTool

def checkCommandOutputAgainOtherCommand(command1, command2, command2Filter=None, ignoreRetCode1=False, ignoreRetCode2=False):

    try:
        output1 = subprocess.check_output(command1)
    except subprocess.CalledProcessError, e:
        if ignoreRetCode1:
            output1 = e.output
        else:
            raise e
    
    try:
        output2 = subprocess.check_output(command2)
    except subprocess.CalledProcessError, e:
        if ignoreRetCode2:
            output2 = e.output
        else:
            raise e
    
    if command2Filter != None:
        output2 = command2Filter(output2)

    if output1 != output2:
        print "output1 = %s" % output1.encode("hex")
        print "output2 = %s" % output2.encode("hex")
        assert False

def checkCommandOutputFixed(command, expectedOutput):
    actualOutput = subprocess.check_output(command)
    if actualOutput != expectedOutput:
        print "actualOutput = %s" % actualOutput.encode("hex")
        print "expectedOutput = %s" % expectedOutput.encode("hex")
        assert False

def checkBase64Encode():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "base64-encode", 
            "-l", 
            pathForResource("test.cer")
        ], [
            "openssl", 
            "enc", 
            "-e", 
            "-base64", 
            "-in", 
            pathForResource("test.cer")
        ]
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "base64-encode", 
            "-l", 
            pathForResource("plaintext-0.dat")
        ], [
            "openssl", 
            "enc", 
            "-e", 
            "-base64", 
            "-in", 
            pathForResource("plaintext-0.dat")
        ]
    )

def checkBase64Decode():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "base64-decode", 
            pathForResource("test.pem")
        ], [
            "openssl", 
            "enc", 
            "-d", 
            "-base64", 
            "-in", 
            pathForResource("test.pem")
        ]
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "base64-decode", 
            pathForResource("plaintext-0.dat")
        ], [
            "openssl", 
            "enc", 
            "-d", 
            "-base64", 
            "-in", 
            pathForResource("plaintext-0.dat")
        ]
    )

def checkMD5Digest():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "md5-digest", 
            pathForResource("test.cer")
        ], [
            "openssl", 
            "dgst", 
            "-md5", 
            pathForResource("test.cer")
        ], 
        lambda s : s[s.index("=")+2:]
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "md5-digest", 
            pathForResource("plaintext-0.dat")
        ], [
            "openssl", 
            "dgst", 
            "-md5", 
            pathForResource("plaintext-0.dat")
        ], 
        lambda s : s[s.index("=")+2:]
    )

def checkSHA1Digest():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "sha1-digest", 
            pathForResource("test.cer")
        ], [
            "openssl", 
            "dgst", 
            "-sha1", 
            pathForResource("test.cer")
        ], 
        lambda s : s[s.index("=")+2:]
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "sha1-digest", 
            pathForResource("plaintext-0.dat")
        ], [
            "openssl", 
            "dgst", 
            "-sha1", 
            pathForResource("plaintext-0.dat")
        ], 
        lambda s : s[s.index("=")+2:]
    )

def checkHMACSHA1():
    # AFAICT the version of OpenSSL installed on OS X does not let us 
    # specify the key as hex, so we have to rely or its key derivation 
    # here.  It seems it just uses the bytes of the key string as the 
    # key, and thus we do the same (using UTF-8 because that's what you 
    # get by default from Terminal).
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "hmac-sha1", 
            "-k", 
            "48656c6c6f20437275656c20576f726c6421", 
            pathForResource("test.cer")
        ], [
            "openssl", 
            "dgst", 
            "-sha1", 
            "-hmac", 
            "Hello Cruel World!", 
            pathForResource("test.cer")
        ], 
        lambda s : s[s.index("=")+2:]
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "hmac-sha1", 
            "-k", 
            "", 
            pathForResource("test.cer")
        ], [
            "openssl", 
            "dgst", 
            "-sha1", 
            "-hmac", 
            "", 
            pathForResource("test.cer")
        ], 
        lambda s : s[s.index("=")+2:]
    )

def checkPBKDF2KeyDerivation():
    # AFAICT there's no way to get the OpenSSL command line tool to do PBKDF2 )-:
    pass

def checkAES128ECBEncryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-encrypt", 
            "-e", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            pathForResource("plaintext-336.dat")
        ], [
            "openssl", 
            "enc", 
            "-e", 
            "-aes-128-ecb", 
            "-nopad", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-in", 
            pathForResource("plaintext-336.dat")
        ]
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-encrypt", 
            "-e", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            pathForResource("plaintext-0.dat")
        ], [
            "openssl", 
            "enc", 
            "-e", 
            "-aes-128-ecb", 
            "-nopad", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-in", 
            pathForResource("plaintext-0.dat")
        ]
    )

def checkAES128ECBDecryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-decrypt", 
            "-e", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            pathForResource("cyphertext-aes-128-ecb-336.dat")
        ], [
            "openssl", 
            "enc", 
            "-d", 
            "-aes-128-ecb", 
            "-nopad", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-in", 
            pathForResource("cyphertext-aes-128-ecb-336.dat")
        ]
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-decrypt", 
            "-e", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            pathForResource("plaintext-0.dat")
        ], [
            "openssl", 
            "enc", 
            "-d", 
            "-aes-128-ecb", 
            "-nopad", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-in", 
            pathForResource("plaintext-0.dat")
        ]
    )

def checkAES128CBCEncryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-encrypt", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-i", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            pathForResource("plaintext-336.dat")
        ], [
            "openssl", 
            "enc", 
            "-e", 
            "-aes-128-cbc", 
            "-nopad", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-iv", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            "-in", 
            pathForResource("plaintext-336.dat")
        ]
    )

def checkAES128CBCDecryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-decrypt", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-i", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            pathForResource("cyphertext-aes-128-cbc-336.dat")
        ], [
            "openssl", 
            "enc", 
            "-d", 
            "-aes-128-cbc", 
            "-nopad", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-iv", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            "-in", 
            pathForResource("cyphertext-aes-128-cbc-336.dat")
        ]
    )

def checkAES256ECBEncryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-encrypt", 
            "-e", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            pathForResource("plaintext-336.dat")
        ], [
            "openssl", 
            "enc", 
            "-e", 
            "-aes-256-ecb", 
            "-nopad", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            "-in", 
            pathForResource("plaintext-336.dat")
        ]
    )

def checkAES256ECBDecryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-decrypt", 
            "-e", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            pathForResource("cyphertext-aes-256-ecb-336.dat")
        ], [
            "openssl", 
            "enc", 
            "-d", 
            "-aes-256-ecb", 
            "-nopad", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            "-in", 
            pathForResource("cyphertext-aes-256-ecb-336.dat")
        ]
    )

def checkAES256CBCEncryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-encrypt", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            "-i", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            pathForResource("plaintext-336.dat")
        ], [
            "openssl", 
            "enc", 
            "-e", 
            "-aes-256-cbc", 
            "-nopad", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            "-iv", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            "-in", 
            pathForResource("plaintext-336.dat")
        ]
    )

def checkAES256CBCDecryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-decrypt", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            "-i", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            pathForResource("cyphertext-aes-256-cbc-336.dat")
        ], [
            "openssl", 
            "enc", 
            "-d", 
            "-aes-256-cbc", 
            "-nopad", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            "-iv", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            "-in", 
            pathForResource("cyphertext-aes-256-cbc-336.dat")
        ]
    )

# ---------------------------------------------------------------------------

def checkAES128PadCBCEncryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-pad-encrypt", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-i", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            pathForResource("plaintext-332.dat")
        ], [
            "openssl", 
            "enc", 
            "-e", 
            "-aes-128-cbc", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-iv", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            "-in", 
            pathForResource("plaintext-332.dat")
        ]
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-pad-encrypt", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-i", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            pathForResource("plaintext-0.dat")
        ], [
            "openssl", 
            "enc", 
            "-e", 
            "-aes-128-cbc", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-iv", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            "-in", 
            pathForResource("plaintext-0.dat")
        ]
    )

def checkAES128PadCBCDecryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-pad-decrypt", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-i", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            pathForResource("cyphertext-aes-128-cbc-332.dat")
        ], [
            "openssl", 
            "enc", 
            "-d", 
            "-aes-128-cbc", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-iv", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            "-in", 
            pathForResource("cyphertext-aes-128-cbc-332.dat")
        ]
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-pad-decrypt", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-i", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            pathForResource("cyphertext-aes-128-cbc-0.dat")
        ], [
            "openssl", 
            "enc", 
            "-d", 
            "-aes-128-cbc", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D", 
            "-iv", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            "-in", 
            pathForResource("cyphertext-aes-128-cbc-0.dat")
        ]
    )

def checkAES128PadBigCBCEncryption():
    ourEncryptedOutput = tempfile.NamedTemporaryFile()
    theirDecryptedOutput = tempfile.NamedTemporaryFile()

    subprocess.check_call([
        pathForTool(), 
        "aes-pad-big-encrypt", 
        "-k", 
        "0C1032520302EC8537A4A82C4EF7579D", 
        "-i", 
        "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
        "/mach_kernel", 
        ourEncryptedOutput.name
    ])

    subprocess.check_call([
        "openssl", 
        "enc", 
        "-d", 
        "-aes-128-cbc", 
        "-K", 
        "0C1032520302EC8537A4A82C4EF7579D", 
        "-iv", 
        "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
        "-in", 
        ourEncryptedOutput.name, 
        "-out", 
        theirDecryptedOutput.name
    ])

    subprocess.check_call([
        "cmp", 
        "/mach_kernel", 
        theirDecryptedOutput.name
    ])
    
    ourEncryptedOutput.close();
    theirDecryptedOutput.close();

def checkAES128PadBigCBCDecryption():
    theirEncryptedOutput = tempfile.NamedTemporaryFile()
    ourDecryptedOutput = tempfile.NamedTemporaryFile()

    subprocess.check_call([
        "openssl", 
        "enc", 
        "-e", 
        "-aes-128-cbc", 
        "-K", 
        "0C1032520302EC8537A4A82C4EF7579D", 
        "-iv", 
        "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
        "-in", 
        "/mach_kernel", 
        "-out", 
        theirEncryptedOutput.name
    ])

    subprocess.check_call([
        pathForTool(), 
        "aes-pad-big-decrypt", 
        "-k", 
        "0C1032520302EC8537A4A82C4EF7579D", 
        "-i", 
        "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
        theirEncryptedOutput.name, 
        ourDecryptedOutput.name
    ])

    subprocess.check_call([
        "cmp", 
        "/mach_kernel", 
        ourDecryptedOutput.name
    ])

    theirEncryptedOutput.close();
    ourDecryptedOutput.close();

def checkAES256PadCBCEncryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-pad-encrypt", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            "-i", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            pathForResource("plaintext-332.dat")
        ], [
            "openssl", 
            "enc", 
            "-e", 
            "-aes-256-cbc", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            "-iv", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            "-in", 
            pathForResource("plaintext-332.dat")
        ]
    )

def checkAES256PadCBCDecryption():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "aes-pad-decrypt", 
            "-k", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            "-i", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            pathForResource("cyphertext-aes-256-cbc-332.dat")
        ], [
            "openssl", 
            "enc", 
            "-d", 
            "-aes-256-cbc", 
            "-K", 
            "0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a", 
            "-iv", 
            "AB5BBEB426015DA7EEDCEE8BEE3DFFB7", 
            "-in", 
            pathForResource("cyphertext-aes-256-cbc-332.dat")
        ]
    )

# IMPORTANT: For the following to work you must import TestData/public.pem 
# into the keychain and name it "Imported Public Key".

def checkRSAVerifySHA1Digest():
    def normaliseVerificationOutput(s):
        if s == "Verified OK\n":
            result = "verified\n"
        elif s == "Verification Failure\n":
            result = "not verified\n"
        else:
            assert False
        return result

    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "rsa-sha1-verify", 
            "Imported Public Key",
            pathForResource("test.cer.sig"),
            pathForResource("test.cer")
        ], [
            "openssl", 
            "dgst", 
            "-sha1", 
            "-verify", 
            pathForResource("public.pem"), 
            "-signature", 
            pathForResource("test.cer.sig"), 
            pathForResource("test.cer")
        ], 
        normaliseVerificationOutput, 
        ignoreRetCode2=True
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "rsa-sha1-verify", 
            "Imported Public Key",
            pathForResource("test.cer.sig"),
            pathForResource("test-corrupted.cer")
        ], [
            "openssl", 
            "dgst", 
            "-sha1", 
            "-verify", 
            pathForResource("public.pem"), 
            "-signature", 
            pathForResource("test.cer.sig"), 
            pathForResource("test-corrupted.cer")
        ], 
        normaliseVerificationOutput, 
        ignoreRetCode2=True
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "rsa-sha1-verify", 
            "Imported Public Key",
            pathForResource("plaintext-0.dat.sig"),
            pathForResource("plaintext-0.dat")
        ], [
            "openssl", 
            "dgst", 
            "-sha1", 
            "-verify", 
            pathForResource("public.pem"), 
            "-signature", 
            pathForResource("plaintext-0.dat.sig"),
            pathForResource("plaintext-0.dat")
        ], 
        normaliseVerificationOutput, 
        ignoreRetCode2=True
    )

def checkRSASignSHA1Digest():
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "rsa-sha1-sign", 
            "Imported Private Key", 
            pathForResource("test.cer")
        ], [
            "openssl", 
            "dgst", 
            "-sha1", 
            "-sign", 
            pathForResource("private.pem"), 
            pathForResource("test.cer"), 
        ], 
        lambda s : s.encode("hex") + "\n"
    )
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "rsa-sha1-sign", 
            "Imported Private Key", 
            pathForResource("plaintext-0.dat")
        ], [
            "openssl", 
            "dgst", 
            "-sha1", 
            "-sign", 
            pathForResource("private.pem"), 
            pathForResource("plaintext-0.dat"), 
        ], 
        lambda s : s.encode("hex") + "\n"
    )

def checkRSASmallEncrypt():
    # In the no-pad can we can explicitly compare the output.
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "rsa-small-encrypt", 
            "-p", 
            "none", 
            "Imported Public Key", 
            pathForResource("plaintext-256.dat")
        ], [
            "openssl", 
            "rsautl",
            "-encrypt",
            "-raw",
            "-pubin",
            "-inkey",
            "TestData/public.pem",
            "-in",
            pathForResource("plaintext-256.dat")
        ], 
        lambda s : s.encode("hex") + "\n"
    )
    # In the PKCS#1 padding case we have OpenSSL decrypt our results.
    cypherText = subprocess.check_output([
            pathForTool(), 
            "rsa-small-encrypt", 
            "Imported Public Key", 
            pathForResource("plaintext-32.dat")
    ])
    assert cypherText[-1] == "\n"
    cypherText = cypherText[:-1]
    cypherTextFile = tempfile.NamedTemporaryFile()
    cypherTextFile.write(cypherText.decode("hex"))
    cypherTextFile.flush()
    decryptedCypherText = subprocess.check_output([
            "openssl", 
            "rsautl",
            "-decrypt",
            "-pkcs",
            "-inkey",
            "TestData/private.pem",
            "-in",
            cypherTextFile.name
    ])
    cypherTextFile.close()
    assert decryptedCypherText == open(pathForResource("plaintext-32.dat")).read()

def checkRSASmallDecrypt():
    # In the no-pad can we can explicitly compare the output.
    checkCommandOutputAgainOtherCommand([
            pathForTool(), 
            "rsa-small-decrypt", 
            "-p", 
            "none", 
            "Imported Private Key", 
            pathForResource("cyphertext-rsa-nopad-256.dat")
        ], [
            "openssl", 
            "rsautl",
            "-decrypt",
            "-raw",
            "-inkey",
            "TestData/private.pem",
            "-in",
            pathForResource("cyphertext-rsa-nopad-256.dat")
        ], 
        lambda s : s.encode("hex") + "\n"
    )
    # In the PKCS#1 padding case we decrypt OpenSSL's results.
    cypherText = subprocess.check_output([
            "openssl", 
            "rsautl",
            "-encrypt",
            "-pkcs",
            "-pubin",
            "-inkey",
            "TestData/public.pem",
            "-in",
            pathForResource("plaintext-32.dat")
    ])
    cypherTextFile = tempfile.NamedTemporaryFile()
    cypherTextFile.write(cypherText)
    cypherTextFile.flush()
    decryptedCypherText = subprocess.check_output([
            pathForTool(), 
            "rsa-small-decrypt", 
            "Imported Private Key", 
            cypherTextFile.name
    ])
    cypherTextFile.close()
    assert decryptedCypherText == (open(pathForResource("plaintext-32.dat")).read().encode("hex") + "\n")

setupPathForTool();

checkBase64Encode()
checkBase64Decode()

checkMD5Digest()
checkSHA1Digest()
checkHMACSHA1()

checkPBKDF2KeyDerivation()

checkAES128ECBEncryption()
checkAES128ECBDecryption()
checkAES128CBCEncryption()
checkAES128CBCDecryption()

checkAES256ECBEncryption()
checkAES256ECBDecryption()
checkAES256CBCEncryption()
checkAES256CBCDecryption()

# I'm not exercising the Pad + ECB case because ECB is a bad idea and 
# I don't want to encourage it.

checkAES128PadCBCEncryption()
checkAES128PadCBCDecryption()
checkAES128PadBigCBCEncryption()
checkAES128PadBigCBCDecryption()
checkAES256PadCBCEncryption()
checkAES256PadCBCDecryption()

checkRSAVerifySHA1Digest()
checkRSASignSHA1Digest()
checkRSASmallEncrypt()
checkRSASmallDecrypt()

print "Success"
