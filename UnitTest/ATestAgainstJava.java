/*
     File: ATestAgainstJava.java
 Abstract: Shows how to generate results compatible with our code from Java.
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

// This test was run on OS X 10.8.4 with the built-in version of Java (that is, the Java 
// that gets installed when you type "javac" at the command line).  The version info was:
//
// $ java -version
// java version "1.6.0_51"
// Java(TM) SE Runtime Environment (build 1.6.0_51-b11-457-11M4509)
// Java HotSpot(TM) 64-Bit Server VM (build 20.51-b01-457, mixed mode)
//
// To run the test:
//
// $ cd UnitTest
// $ javac ATestAgainstJava.java && java -ea Main
//
// Note that this code isn't intended to be a good example of Java programming; it's merely 
// sufficient to test the things I needed to test.

import java.lang.*;
import java.util.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.bind.DatatypeConverter;

class QHex
{
    public static String hexStringFromBytes(byte[] bytes)
    {
        return DatatypeConverter.printHexBinary(bytes).toLowerCase();
    }

    public static byte[] bytesFromHexString(String string)
    {
        return DatatypeConverter.parseHexBinary(string);
    }
}

class QIO
{
    public static byte[] bytesWithContentsOfFile(String fileName) throws IOException, NoSuchAlgorithmException
    {
        RandomAccessFile f = new RandomAccessFile("../TestData/" + fileName, "r");
        byte[] bytes = new byte[(int) f.length()];
        f.readFully(bytes);
        f.close();
        return bytes;
    }

    public static String stringWithContentsOfFile(String fileName) throws IOException, NoSuchAlgorithmException
    {
        return new String(QIO.bytesWithContentsOfFile(fileName), "UTF-8");
    }
    
    public static byte[] bytesWithDecodedContentsOfPEMFile(String fileName, String tag) throws IOException, NoSuchAlgorithmException
    {
        String pemStr = QIO.stringWithContentsOfFile(fileName);
        String beginMarker = "-----BEGIN " + tag + "-----\n";
        String endMarker = "-----END " + tag + "-----";
        pemStr = pemStr.substring(pemStr.indexOf(beginMarker, 0));
        // System.out.format("%s", pemStr);
        pemStr = pemStr.replace(beginMarker, "");
        pemStr = pemStr.replace(endMarker, "");
        return DatatypeConverter.parseBase64Binary(pemStr);
    }
    
    public static FileInputStream fileInputStreamForFile(String fileName) throws FileNotFoundException
    {
        return new FileInputStream("../TestData/" + fileName);
    }
}

class Base64Tests
{
    public static void testBase64Encode() throws IOException, NoSuchAlgorithmException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("test.cer");
        String expectedOutputString = QIO.stringWithContentsOfFile("test.pem");
        expectedOutputString = expectedOutputString.replace("\n", "");      // there's no way to tell printBase64Binary to add line breaks, so we strip them from the expected string
        String outputString = DatatypeConverter.printBase64Binary(inputBytes);
        assert outputString.equals(expectedOutputString);
    }

    public static void testBase64Decode() throws IOException, NoSuchAlgorithmException
    {
        String inputString = QIO.stringWithContentsOfFile("test.pem");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("test.cer");
        byte[] outputBytes = DatatypeConverter.parseBase64Binary(inputString);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    }
}

class DigestTests
{
    public static void testMD5() throws IOException, NoSuchAlgorithmException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("test.cer");
        byte[] expectedOutputBytes = QHex.bytesFromHexString("cdd202dcf9deea872f7c64f6081e526c");
        byte[] outputBytes = MessageDigest.getInstance("MD5").digest(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    }

    public static void testSHA1() throws IOException, NoSuchAlgorithmException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("test.cer");
        byte[] expectedOutputBytes = QHex.bytesFromHexString("c1ddfe7dd14c9b8dee83b46b87a408970fd2a83f");
        byte[] outputBytes = MessageDigest.getInstance("SHA1").digest(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    }

    public static void testHMACSHA1() throws IOException, NoSuchAlgorithmException, InvalidKeyException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("test.cer");
        byte[] keyBytes = QHex.bytesFromHexString("48656c6c6f20437275656c20576f726c6421");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "HmacSHA1");
        byte[] expectedOutputBytes = QHex.bytesFromHexString("550a1da058c1b5df6ea167870ae6dbc92f0e0281");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(keySpec);
        byte[] outputBytes = mac.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    }
}

class KeyDerivationTests
{
    public static void testPBKDF2() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        String passwordString = "Hello Cruel World!";
        byte[] saltBytes = "Some salt sir?".getBytes("UTF-8");
        byte[] expectedKeyBytes = QHex.bytesFromHexString("e56c27f5eed251db50a3");
        PBEKeySpec keySpec = new PBEKeySpec(passwordString.toCharArray(), saltBytes, 1000, 10 * 8);      // keyLength is in bits!
        byte[] keyBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(keySpec).getEncoded();
        assert Arrays.equals(keyBytes, expectedKeyBytes);
    }
}

class CryptorTests
{
    // AES-128
    
    public static void testAES128ECBEncryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("plaintext-336.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-128-ecb-336.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    }

    public static void testAES128ECBDecryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-128-ecb-336.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("plaintext-336.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    } 

    public static void testAES128CBCEncryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("plaintext-336.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-128-cbc-336.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D");
        byte[] ivBytes = QHex.bytesFromHexString("AB5BBEB426015DA7EEDCEE8BEE3DFFB7");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(ivBytes));
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    }

    public static void testAES128CBCDecryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-128-cbc-336.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("plaintext-336.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D");
        byte[] ivBytes = QHex.bytesFromHexString("AB5BBEB426015DA7EEDCEE8BEE3DFFB7");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivBytes));
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    } 

    // AES-256
    
    public static void testAES256ECBEncryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("plaintext-336.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-256-ecb-336.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    }

    public static void testAES256ECBDecryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-256-ecb-336.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("plaintext-336.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    } 

    public static void testAES256CBCEncryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("plaintext-336.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-256-cbc-336.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a");
        byte[] ivBytes = QHex.bytesFromHexString("AB5BBEB426015DA7EEDCEE8BEE3DFFB7");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(ivBytes));
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    }

    public static void testAES256CBCDecryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-256-cbc-336.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("plaintext-336.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a");
        byte[] ivBytes = QHex.bytesFromHexString("AB5BBEB426015DA7EEDCEE8BEE3DFFB7");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivBytes));
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    } 

    // AES-128 Pad CBC
    
    public static void testAES128PadCBCEncryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("plaintext-332.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-128-cbc-332.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D");
        byte[] ivBytes = QHex.bytesFromHexString("AB5BBEB426015DA7EEDCEE8BEE3DFFB7");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(ivBytes));
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    }

    public static void testAES128PadCBCDecryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-128-cbc-332.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("plaintext-332.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D");
        byte[] ivBytes = QHex.bytesFromHexString("AB5BBEB426015DA7EEDCEE8BEE3DFFB7");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivBytes));
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    } 

    // AES-256 Pad CBC
    
    public static void testAES256PadCBCEncryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("plaintext-332.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-256-cbc-332.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a");
        byte[] ivBytes = QHex.bytesFromHexString("AB5BBEB426015DA7EEDCEE8BEE3DFFB7");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(ivBytes));
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    }

    public static void testAES256PadCBCDecryption() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
        byte[] inputBytes = QIO.bytesWithContentsOfFile("cyphertext-aes-256-cbc-332.dat");
        byte[] expectedOutputBytes = QIO.bytesWithContentsOfFile("plaintext-332.dat");
        byte[] keyBytes = QHex.bytesFromHexString("0C1032520302EC8537A4A82C4EF7579D2b88e4309655eb40707decdb143e328a");
        byte[] ivBytes = QHex.bytesFromHexString("AB5BBEB426015DA7EEDCEE8BEE3DFFB7");
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivBytes));
        byte[] outputBytes = cipher.doFinal(inputBytes);
        assert Arrays.equals(outputBytes, expectedOutputBytes);
    } 
}

class RSATests
{
    static PrivateKey sPrivateKey;
    static PublicKey  sPublicKey;
    
    public static void setup() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, InvalidKeySpecException
    {
        // private key
        
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(QIO.fileInputStreamForFile("private.p12"), null);
        if (false) {
            for (Enumeration<String> e = keyStore.aliases(); e.hasMoreElements(); ) {
                System.out.format("%s\n", e.nextElement());
            }
        }
        sPrivateKey = (PrivateKey) keyStore.getKey("testprivatekey", "test".toCharArray());

        // public key
        
        byte[] publicKeyBytes = QIO.bytesWithDecodedContentsOfPEMFile("public.pem", "PUBLIC KEY");
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        sPublicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    static boolean verifyFile(String fileName) throws IOException, FileNotFoundException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException
    {
        byte[] fileBytes = QIO.bytesWithContentsOfFile(fileName + ".cer");
        byte[] signatureBytes = QIO.bytesWithContentsOfFile("test.cer.sig");
        assert sPublicKey != null;          // set up by setup() method

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(sPublicKey);
        sig.update(fileBytes);
        return sig.verify(signatureBytes);
    }
    
    public static void testRSASHA1Verify() throws IOException, FileNotFoundException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException
    {
        assert RSATests.verifyFile("test");
        assert ! RSATests.verifyFile("test-corrupted");
    }
    
    public static void testRSASHA1Sign() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException
    {
        byte[] fileBytes = QIO.bytesWithContentsOfFile("test.cer");
        byte[] expectedSignatureBytes = QIO.bytesWithContentsOfFile("test.cer.sig");
        assert sPrivateKey != null;         // set up by setup() method

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(sPrivateKey);
        sig.update(fileBytes);
        byte[] signatureBytes = sig.sign();
        
        assert Arrays.equals(signatureBytes, expectedSignatureBytes);
    }

    public static void testRSASmallCryptor() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException
    {
        byte[] fileBytes = QIO.bytesWithContentsOfFile("plaintext-32.dat");
        assert sPublicKey != null;          // set up by setup() method
        assert sPrivateKey != null;         // set up by setup() method
        
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sPublicKey);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);
        
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, sPrivateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        
        assert Arrays.equals(decryptedBytes, fileBytes);
    }

    // We can't test a fixed encryption in the padding case because the padding adds some 
    // randomness so that no two encryptions are the same.

    public static void testRSADecrypt() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException
    {
        byte[] cyphertext32Bytes = QIO.bytesWithContentsOfFile("cyphertext-rsa-pkcs1-32.dat");
        byte[] fileBytes = QIO.bytesWithContentsOfFile("plaintext-32.dat");
        assert sPublicKey != null;          // set up by setup() method
        assert sPrivateKey != null;         // set up by setup() method

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, sPrivateKey);
        byte[] decryptedBytes = cipher.doFinal(cyphertext32Bytes);
        
        assert Arrays.equals(decryptedBytes, fileBytes);
    }
    
    public static void testRSAEncryptNoPad() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException
    {
        byte[] fileBytes = QIO.bytesWithContentsOfFile("plaintext-256.dat");
        byte[] cyphertext256Bytes = QIO.bytesWithContentsOfFile("cyphertext-rsa-nopad-256.dat");
        assert sPublicKey != null;          // set up by setup() method
        assert sPrivateKey != null;         // set up by setup() method

        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sPublicKey);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);
        
        assert Arrays.equals(encryptedBytes, cyphertext256Bytes);
    }

    public static void testRSADecryptNoPad() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException
    {
        byte[] cyphertext256Bytes = QIO.bytesWithContentsOfFile("cyphertext-rsa-nopad-256.dat");
        byte[] fileBytes = QIO.bytesWithContentsOfFile("plaintext-256.dat");
        assert sPublicKey != null;          // set up by setup() method
        assert sPrivateKey != null;         // set up by setup() method

        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, sPrivateKey);
        byte[] decryptedBytes = cipher.doFinal(cyphertext256Bytes);
        
        assert Arrays.equals(decryptedBytes, fileBytes);
    }
}

class Main
{
	public static void main (String[] args) throws Exception
	{
        Base64Tests.testBase64Encode();
        Base64Tests.testBase64Decode();
        DigestTests.testMD5();
        DigestTests.testSHA1();
        DigestTests.testHMACSHA1();
        KeyDerivationTests.testPBKDF2();
        CryptorTests.testAES128ECBEncryption();
        CryptorTests.testAES128ECBDecryption();
        CryptorTests.testAES128CBCEncryption();
        CryptorTests.testAES128CBCDecryption();
        CryptorTests.testAES256ECBEncryption();
        CryptorTests.testAES256ECBDecryption();
        CryptorTests.testAES256CBCEncryption();
        CryptorTests.testAES256CBCDecryption();
        CryptorTests.testAES128PadCBCEncryption();
        CryptorTests.testAES128PadCBCDecryption();
        CryptorTests.testAES256PadCBCEncryption();
        CryptorTests.testAES256PadCBCDecryption();
	    RSATests.setup();
        RSATests.testRSASHA1Verify();
        RSATests.testRSASHA1Sign();
        RSATests.testRSASmallCryptor();
        RSATests.testRSADecrypt();
        RSATests.testRSAEncryptNoPad();
        RSATests.testRSADecryptNoPad();
	    System.out.format("Success.\n");
	}
}
