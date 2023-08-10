/*
 * Copyright (c) 2016-2023, DB Systel GmbH
 * Copyright (c) 2023, Frank Schwab
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Frank Schwab
 *
 * Example program to show correct and incorrect password storage with the PBKDF2 function
 *
 * @author Frank Schwab
 * @version 2.0.0
 *
 * Changes: 
 *     2015-05-26: V1.0.0: Created
 *     2016-09-22. V2.0.0: Have a choice of hash types
 */
package pbkdf2;

import java.nio.ByteBuffer;
import java.io.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Show correct and incorrect PBKDF2 usage in Java
 */
public class PBKDF2Java {

   /*
    * Minimum and maximum values for the integer salt
    */
   private static final int MIN_HASH_TYPE = 1;
   private static final int MAX_HASH_TYPE = 5;

   /*
    * Minimum and maximum values for the integer salt
    */
   private static final int MIN_SALT = 0;
   private static final int MAX_SALT = Integer.MAX_VALUE;

   /*
    * Minimum and maximum values for the iteration count
    */
   private static final int MIN_ITERATION_COUNT = 1;
   private static final int MAX_ITERATION_COUNT = 5000000;

   /**
    * Get an integer from an argument and check its validity
    *
    * @param argName Name of the integer argument
    * @param arg The string value of the argument as it is present in argv
    * @param minValue The minimum allowed value
    * @param maxValue The maximum allowed value
    * @return Value of @see arg as integer
    * @throws IllegalArgumentException
    */
   private static int getIntegerArg(final String argName, final String arg, final int minValue, final int maxValue)
           throws IllegalArgumentException {
      int result;

      try {
         result = Integer.parseInt(arg);
      } catch (NumberFormatException e) {
         throw new IllegalArgumentException(String.format("\"%s\" is not an integer", argName));
      }

      if (result < minValue) {
         throw new IllegalArgumentException(String.format("\"%s\" is smaller than minimum value of %d", argName, minValue));
      }

      if (result > maxValue) {
         throw new IllegalArgumentException(String.format("\"%s\" is larger than maximum value of %d", argName, maxValue));
      }

      return result;
   }

   /**
    * Convert a string of hexadecimal characters into a byte array
    *
    * @param argName Name of the argument
    * @param aHexString String of hexadecimal characters
    * @return Hex string converted to a byte array
    * @throws IllegalArgumentException
    */
   private static byte[] safeHexStringToByteArray(final String argName, final String aHexString)
           throws IllegalArgumentException {
      int    safeHexStringSize = aHexString.length();
      String safeHexString;

      /*
       * Normalize hex string to have an even number of characters
       */
      if ((safeHexStringSize & 1) != 0) {
         // If the no. of characters is odd prepend a '0'
         safeHexStringSize++;
         safeHexString = '0' + aHexString;
      } else {
         safeHexString = aHexString;
      }

      ByteBuffer result = ByteBuffer.allocate(safeHexStringSize >>> 1);

      int actPos = 0;

      try {
         for (int pos = 0; pos < safeHexStringSize; pos += 2) {
            actPos = pos;

            /*
             * The easiest and fastest way to convert a hex string is to prepend "0x" to it
             * and let Java decode this string
             */
            String actHexText = "0x" + safeHexString.substring(pos, pos + 2);
            byte actByte = Integer.decode(actHexText).byteValue();

            result.put(actByte);
         }
      } catch (NumberFormatException e) {
         throw new IllegalArgumentException(String.format("\"%s\" contains illegal hex value \'%s\' at position %d", argName, safeHexString.substring(actPos, actPos + 1), actPos));
      }

      return result.array();
   }

   /**
    * Convert an integer into a byte array.
    * 
    * Java always stores integers in the big endian format,
    * so a value of "1" will be converted to [0x00, 0x00, 0x00, 0x01].
    *
    * @param anInt Integer to be converted
    * @return Integer as byte array
    */
   private static byte[] integerToByteArray(final int anInt) {
      ByteBuffer intAsArray;

      intAsArray = ByteBuffer.allocate(4);
      intAsArray.putInt(anInt);

      return intAsArray.array();
   }

   /**
    * Array of hex characters for output of hex bytes
    */
   final private static char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

   /**
    * Convert an array of bytes to a string of hexadecimal characters separated
    * by blanks
    *
    * @param bytes Array of bytes
    * @return Array of bytes as a string of hexadecimal characters
    */
   private static String bytesToHex(byte[] bytes) {
      char[] hexChars = new char[bytes.length * 3];

      int offset = 0;

      for (int j = 0; j < bytes.length; j++) {
         int v = bytes[j] & 0xFF;

         hexChars[offset] = HEX_DIGITS[v >>> 4]; offset++;
         hexChars[offset] = HEX_DIGITS[v & 0x0F]; offset++;
         hexChars[offset] = ' '; offset++;
      }

      return new String(hexChars, 0, offset - 1);
   }

   /**
    * Calculate the PBKDF2 value.
    *
    * All characters in the password will be converted to their UTF-8 encoding
    * before the value is calculated.
    *
    * @param hashType Type of the hash that should be used in generating the PBKDF2 value
    * @param keyLength Length of the generated key
    * @param salt Salt that should be used in PBKDF2 calculation as byte array
    * @param iterationCount Iteration count that should be used in PBKDF2
    * calculation
    * @param password Password that should be used in PBKDF2 calculation
    * @return PBKDF2 value for the given parameters as byte array
    * @throws NoSuchAlgorithmException
    * @throws InvalidKeySpecException
    */
   private static byte[] generatePBKDF2(final String hashType, final int keyLength, final byte[] salt, final int iterationCount, final String password)
           throws NoSuchAlgorithmException, InvalidKeySpecException {
      char[] chars = password.toCharArray();

      SecretKeyFactory skf = SecretKeyFactory.getInstance(hashType);
      PBEKeySpec spec = new PBEKeySpec(chars, salt, iterationCount, keyLength);

      /*
       * The "generateSecret" method of the "SecretKeyFactory" for the "PBKDF2"
       * algorithms in Oracle's implementation will convert all characters
       * to their UTF-8 encoding before processing them.
       */
      byte[] result = skf.generateSecret(spec).getEncoded();

      return result;
   }

   /**
    * Convert a string into a byte array of the lower bytes of the characters
    *
    * This method is only called when some debugging statements in this program
    * are uncommented.
    *
    * @param str String to be converted
    * @return Byte array of the characters
    */
   private static byte[] stringToBytesASCII(String str) {
      char[] buffer = str.toCharArray();
      byte[] b = new byte[buffer.length];

      for (int i = 0; i < b.length; i++) {
         b[i] = (byte) (buffer[i] & 0xFF);
      }

      return b;
   }

   /**
    * Main program
    *
    * @param args The command line arguments
    * @throws java.lang.Exception
    */
   public static void main(String[] args) throws Exception {
      final String HASH_ALGORITHM[] = { "PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512", "PBKDF2WithHmacSHA512" };
      final int    HASH_LENGTH[]    = { 160, 256, 384, 512, 512 };
      
      /*
       * This program is intended to be run in a Windows DOS box.
       * So set the code page for "out" to the Windows DOS box code page. Otherwise passwords with
       * umlauts will be printed all wrong.
       */
      System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out), true, "CP850"));

      /*
       * Only start to work if there are enough parameters
       */
      if (args.length >= 4) {
         // If we have a 5. option then this means to do the calculation correctly
         boolean doItRight = (args.length >= 5);

         /*
          // This is some output only used for debugging
          System.out.format("args.length=%d\n", args.length);
          System.out.format("args[0]=\'%s\'\n", args[0]);
          System.out.format("args[1]=\'%s\'\n", args[1]);
          System.out.format("args[2]=\'%s\'\n", args[2]);
          System.out.format("args[3]=\'%s\'\n", args[3]);
          if (doItRight)
          System.out.format("args[4]=\'%s\'\n", args[4]);
          System.out.format("doItRight=%b\n", doItRight);
          System.out.format("pwb=%s\n", bytesToHex(stringToBytesASCII(args[3])));
          */
         
         /*
          * 1. Get the hash type
          */
         int hashType = 0;

         try {
            hashType = getIntegerArg("HashType", args[0], MIN_HASH_TYPE, MAX_HASH_TYPE) - 1;
         } catch (Exception e) {
            e.printStackTrace(System.err);
            System.exit(1);
         }
         
         /*
          * 2. Convert the salt value to an array
          */
         int salt = 0;

         byte[] saltArray = null;

         try {
            if (doItRight) {
               // If we do it right the salt is interpreted as a string of bytes
               saltArray = safeHexStringToByteArray("Salt", args[1]);
            } else {
               // If we do it intentionally wrong the salt is interpreted as an integer
               salt = getIntegerArg("Salt", args[1], MIN_SALT, MAX_SALT);

               saltArray = integerToByteArray(salt);
            }
         } catch (Exception e) {
            e.printStackTrace(System.err);
            System.exit(1);
         }

         /*
          * 3. Get the iteration count
          */
         int iterationCount = 0;

         try {
            iterationCount = getIntegerArg("IterationCount", args[2], MIN_ITERATION_COUNT, MAX_ITERATION_COUNT);
         } catch (Exception e) {
            e.printStackTrace(System.err);
            System.exit(1);
         }

         /*
          * 4. Get the password
          */
         String password = args[3];

//         System.out.format("password: %s\n", bytesToHex(stringToBytesASCII(password)));

         /*
          * 5. Generate the PBKDF2 value and measure the time it took to generate it
          */
         try {
            long   start = System.currentTimeMillis();
            byte[] pbkdf2Value = generatePBKDF2(HASH_ALGORITHM[hashType], HASH_LENGTH[hashType], saltArray, iterationCount, password);
            long   elapsed = System.currentTimeMillis() - start;

            /*
             * Now put out the result with all the parameters
             */
            System.out.format("HashType: %s", HASH_ALGORITHM[hashType].substring(14));
            
            System.out.print(", Salt: ");

            if (doItRight) {
               System.out.format("%s", bytesToHex(saltArray));
            } else {
               System.out.format("%d", salt);
            }

            System.out.format(", IterationCount: %d, Password: \'%s\', PBKDF2: %s\n", iterationCount, password, bytesToHex(pbkdf2Value));

            System.out.format("Duration: %d ms\n", elapsed);
         } catch (Exception e) {
            e.printStackTrace(System.err);
         }
      } else {
         System.err.println("Not enough parameters.\n");
         System.err.println("Usage: pbkdf2java.jar <hashType> <salt> <iterationCount> <password> [doItRight]\n");
         System.err.println("       hashType: 1=SHA-1, 2=SHA-256, 3=SHA384, 5=SHA512");
         System.err.println("       doItRight: If present the salt is interpreted as a byte array");
         System.err.println("                  Otherwise the salt is interpreted as an integer");

         System.exit(1);
      }
   }
}
