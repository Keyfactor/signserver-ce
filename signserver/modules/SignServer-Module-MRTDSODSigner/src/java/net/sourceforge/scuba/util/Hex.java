/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006  SoS group, ICIS, Radboud University
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id: Hex.java 70 2006-07-16 21:55:08Z martijno $
 */

package net.sourceforge.scuba.util;

/**
 * Some static helper methods for dealing with hexadecimal notation.
 *
 * @author Martijn Oostdijk (martijno@cs.ru.nl)
 *
 * @version $Revision: 70 $
 */
public final class Hex {

   /** Hex characters. */
   private static final String HEXCHARS = "0123456789abcdefABCDEF";

   /** Printable characters. */
   private static final String PRINTABLE = " .,:;'`\"<>()[]{}?/\\!@#$%^&*_-=+|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

   private static final boolean LEFT = true;
   private static final boolean RIGHT = false;

   /**
    * This private constructor makes it impossible for clients to create
    * instances of this class.
    */
   private Hex() {
   }

   /**
    * Converts the byte <code>b</code> to capitalized hexadecimal text.
    * The result will have length 2 and only contain the characters '0', '1',
    * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
    *
    * @param b the byte to convert.
    *
    * @return capitalized hexadecimal text representation of <code>b</code>.
    */
   public static String byteToHexString(byte b) {
      int n = b & 0x000000FF;
      String result = (n < 0x00000010 ? "0" : "") + Integer.toHexString(n);
      return result.toUpperCase();
   }

   /**
    * Converts the short <code>s</code> to capitalized hexadecimal text.
    * The result will have length 4 and only contain the characters '0', '1',
    * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
    *
    * @param s the short to convert.
    *
    * @return capitalized hexadecimal text representation of <code>s</code>.
    */
   public static String shortToHexString(short s) {
      int n = s & 0x0000FFFF;
      String result = ((n < 0x00001000) ? "0" : "")
                    + ((n < 0x00000100) ? "0" : "")
                    + ((n < 0x00000010) ? "0" : "")
                    + Integer.toHexString(s);
      if(result.length() > 4) {
          result = result.substring(result.length()-4, result.length()); 
      }
      return result.toUpperCase();
   }

   /**
    * Converts the integer <code>n</code> to capitalized hexadecimal text.
    * The result will have length 8 and only contain the characters '0', '1',
    * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
    *
    * @param n the integer to convert.
    *
    * @return capitalized hexadecimal text representation of <code>n</code>.
    */
   public static String intToHexString(int n) {
      String result = ((n < 0x10000000) ? "0" : "")
                    + ((n < 0x01000000) ? "0" : "")
                    + ((n < 0x00100000) ? "0" : "")
                    + ((n < 0x00010000) ? "0" : "")
                    + ((n < 0x00001000) ? "0" : "")
                    + ((n < 0x00000100) ? "0" : "")
                    + ((n < 0x00000010) ? "0" : "")
                    + Integer.toHexString(n);
      return result.toUpperCase();
   }

   /**
    * Converts a byte array to capitalized hexadecimal text.
    * The length of the resulting string will be twice the length of
    * <code>text</code> and will only contain the characters '0', '1',
    * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
    *
    * @param text The byte array to convert.
    *
    * @return capitalized hexadecimal text representation of
    *    <code>text</code>.
    */
   public static String bytesToHexString(byte[] text) {
      return bytesToHexString(text, 1000);
   }

   public static String bytesToHexString(byte[] text, int numRow) {
       if(text == null) {
           return "NULL";
       }
       return bytesToHexString(text,0,text.length, numRow);
    }
   
   /**
    * Converts a byte array to capitalized hexadecimal text.
    * The length of the resulting string will be twice the length of
    * <code>text</code> and will only contain the characters '0', '1',
    * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
    *
    * @param text The byte array to convert.
    *
    * @return capitalized hexadecimal text representation of
    *    <code>text</code>.
    */
   public static String toHexString(byte[] text) {
      return bytesToHexString(text,0,text.length, 1000);
   }

   
   public static String toHexString(byte[] text, int numRow) {
       return bytesToHexString(text,0,text.length, numRow);
    }

   /**
    * Converts part of a byte array to capitalized hexadecimal text.
    * Conversion starts at index <code>offset</code> until (excluding)
    * index <code>offset + length</code>.
    * The length of the resulting string will be twice the length
    * <code>text</code> and will only contain the characters '0', '1',
    * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
    *
    * @param text the byte array to convert.
    * @param offset where to start.
    * @param length how many bytes to convert.
    * @param numRow number of bytes to be put one in one row of output
    *
    * @return capitalized hexadecimal text representation of
    *    <code>text</code>.
    */
   public static String bytesToHexString(byte[] text, int offset, int length, int numRow) {
      if(text == null) return "NULL";
      String result = "";
      for (int i = 0; i < length; i++) {
         if(i != 0 && i % numRow == 0) result += "\n";
         result += byteToHexString(text[offset + i]);
      }
      return result;
   }

   public static String bytesToHexString(byte[] text, int offset, int length) {
       return bytesToHexString(text, offset, length, 1000);
    }

   
   /**
    * Converts the hexadecimal string in <code>text</code> to 
    * a byte.
    *
    * @return the byte encoded in <code>text</code>.
    *
    * @throws NumberFormatException if <code>text</code> does not contain
    *    a valid hexadecimal byte representation.
    */
   public static byte hexStringToByte(String text)
   throws NumberFormatException {
      byte[] bytes = hexStringToBytes(text);
      if (bytes.length != 1) {
         throw new NumberFormatException();
      }
      return bytes[0];
   }

   /**
    * Converts the hexadecimal string in <code>text</code> to 
    * a short.
    *
    * @return the short encoded in <code>text</code>.
    *
    * @throws NumberFormatException if <code>text</code> does not contain
    *    a valid hexadecimal short representation.
    */
   public static short hexStringToShort(String text)
   throws NumberFormatException {
      byte[] bytes = hexStringToBytes(text);
      if (bytes.length != 2) {
         throw new NumberFormatException();
      }
      return (short)(((bytes[0] & 0x000000FF) << 8)
                    | (bytes[1] & 0x000000FF));
   }

   /**
    * Converts the hexadecimal string in <code>text</code> to
    * an integer.
    *
    * @return the integer encoded in <code>text</code>.
    *
    * @throws NumberFormatException if <code>text</code> does not contain
    *    a valid hexadecimal integer representation.
    */
   public static int hexStringToInt(String text)
   throws NumberFormatException {
      byte[] bytes = hexStringToBytes(text);
      if (bytes.length != 4) {
         throw new NumberFormatException();
      }
      return (int)(((bytes[0] & 0x000000FF) << 24)
                 | ((bytes[1] & 0x000000FF) << 16)
                 | ((bytes[2] & 0x000000FF) << 8)
                 | (bytes[3] & 0x000000FF));
   }

   /**
    * Converts the hexadecimal string in <code>text</code> to
    * a byte array. If <code>text</code> has an odd number of
    * characters, a <code>0</code> is inserted at the beginning.
    *
    * @param text the string to convert.
    *
    * @return the byte array representation of the hexadecimal string
    *    in <code>text</code>.
    *
    * @throws NumberFormatException if <code>text</code> does not contain
    *    a valid hexadecimal string.
    */
   public static byte[] hexStringToBytes(String text)
   throws NumberFormatException {
      if (text==null) {
         return null;
      }
      StringBuffer hexText = new StringBuffer();
      for (int i=0; i < text.length(); i++) {
         char c = text.charAt(i);
         if (Character.isWhitespace(c)) {
            continue;
         } else if (HEXCHARS.indexOf(c) < 0) {
            throw new NumberFormatException();
         } else {
            hexText.append(c);
         }
      }
      if (hexText.length() % 2 != 0) {
         hexText.insert(0,"0");
      }
      byte[] result = new byte[hexText.length() / 2];
      for (int i = 0; i < hexText.length(); i += 2) {
         int hi = hexDigitToInt(hexText.charAt(i));
         int lo = hexDigitToInt(hexText.charAt(i + 1));
         result[i / 2] = (byte)(((hi & 0x000000FF) << 4) | (lo & 0x000000FF));
      }
      return result;
   }

   /**
    * Interprets the character <code>c</code> as hexadecimal digit.
    *
    * @param c a character from '0', '1', '2', '3', '4', '5', '6', '7', '8',
    *    '9', 'A', 'B', 'C', 'D', 'E', 'F'.
    *
    * @return the decimal-hexadecimal digit interpretation of
    *    <code>c</code>.
    */
   static int hexDigitToInt(char c)
   throws NumberFormatException {
      switch (c) {
         case '0': return 0;
         case '1': return 1;
         case '2': return 2;
         case '3': return 3;
         case '4': return 4;
         case '5': return 5;
         case '6': return 6;
         case '7': return 7;
         case '8': return 8;
         case '9': return 9;
         case 'a': case 'A': return 10;
         case 'b': case 'B': return 11;
         case 'c': case 'C': return 12;
         case 'd': case 'D': return 13;
         case 'e': case 'E': return 14;
         case 'f': case 'F': return 15;
         default: throw new NumberFormatException();
      }
   }

   /**
    * Pads <code>txt</code> with <code>padChar</code> characters so
    * that its length becomes <code>width</code>. If the length
    * of <code>txt</code> is already greater or equal to <code>width</code>,
    * the result is just a copy of <code>txt</code>.
    *
    * @param txt the string to pad.
    * @param width the length of the result (unless the length of
    *    <code>txt</code> was already greater or equal to <code>width</code>.
    * @param padChar the padding character.
    * @param left a boolean indicating whether to pad to the left
    *    (<code>true</code>) or to the right (<code>false</code>).
    *
    * @return the padded text.
    */
   private static String pad(String txt, int width, char padChar, boolean left) {
      String result = new String(txt);
      String padString = Character.toString(padChar);
      for (int i = txt.length(); i < width; i++) {
         if (left) {
            result = padString + result;
         } else {
            result = result + padString;
         }
      }
      return result;
   }

   /**
    * Hexadecimal representation of <code>data</code> with spaces between
    * individual bytes.
    *
    * @param data the byte array to print.
    *
    * @return spaced hexadecimal representation of <code>data</code>.
    */
   public static String bytesToSpacedHexString(byte[] data) {
      String result = "";
      for (int i = 0; i < data.length; i++) {
         result += byteToHexString(data[i]);
         result += (i < data.length - 1) ? " " : "";
      }
      result = result.toUpperCase();
      return result;
   }

   /**
    * Hexadecimal representations of <code>data</code> with spaces between
    * individual bytes. Each string represents <code>columns</code> bytes,
    * except for the last one, which represents at most <code>columns</code>
    * bytes.
    *
    * @param data the byte array to represent.
    * @param columns the width of each line.
    * @param padWidth resulting strings will be padded to this length with
    *    spaces to the right.
    *
    * @return spaced hexadecimal representations of <code>data</code>.
    */
   private static String[] bytesToSpacedHexStrings(byte[] data, int columns,
                                           int padWidth) {
      byte[][] src = split(data,columns);
      String[] result = new String[src.length];
      for (int j = 0; j < src.length; j++) {
         result[j] = bytesToSpacedHexString(src[j]);
         result[j] = pad(result[j],padWidth,' ',RIGHT);
      }
      return result;
   }

   public static String bytesToASCIIString(byte[] data) {
      String result = "";
      for (int i = 0; i < data.length; i++) {
         char c = (char)data[i];
         result += Character.toString(PRINTABLE.indexOf(c) >= 0 ? c : '.');
      }
      return result;
   }

   /**
    * ASCII representations of <code>data</code>.
    * Each string represents <code>columns</code> bytes, except for the last
    * one, which represents at most <code>columns</code> bytes.
    *
    * @param data the byte array to represent.
    * @param columns the width of each line.
    * @param padWidth resulting strings will be padded to this length with
    *    spaces to the right.
    *
    * @return spaced hexadecimal representations of <code>data</code>.
    */
   static String[] bytesToASCIIStrings(byte[] data, int columns,
                                       int padWidth) {
      byte[][] src = split(data,columns);
      String[] result = new String[src.length];
      for (int j = 0; j < src.length; j++) {
         result[j] = bytesToASCIIString(src[j]);
      }
      return result;
   }

   /**
    * Splits the byte array <code>src</code> into a number of byte arrays of
    * length <code>width</code>. (Plus one of length less than width if
    * <code>width</code> does not divide the length of <code>src</code>.)
    *
    * @param src the byte array to split.
    * @param width a positive number.
    */
   public static byte[][] split(byte[] src, int width) {
      int rows = src.length / width;
      int rest = src.length % width;
      byte[][] dest = new byte[rows + (rest > 0 ? 1 : 0)][];
      int k = 0;
      for (int j = 0; j < rows; j++) {
         dest[j] = new byte[width];
         System.arraycopy(src,k,dest[j],0,width);
         k += width;
      }
      if (rest > 0) {
         dest[rows] = new byte[rest];
         System.arraycopy(src,k,dest[rows],0,rest);
      }
      return dest;
   }

   /**
    * Gets a human readable hexadecimal representation of <code>data</code>
    * with spaces.
    * Includes and index and ASCII representation.
    *
    * @param data the byte array to print.
    *
    * @return a hexadecimal representation of <code>data</code>.
    */
   public static String bytesToPrettyString(byte[] data) {
      return bytesToPrettyString(data,16,true,4,null,true);
   }

   /**
    * Gets a human readable hexadecimal representation of <code>data</code>
    * with spaces and newlines in <code>columns</code> columns.
    * Will print an index before each line if <code>useIndex</code> is
    * <code>true</code>.
    * Will print an ASCII representation after each line if
    * <code>useASCII</code> is <code>true</code>.
    *
    * @param data the byte array to print.
    * @param columns the number of bytes per line.
    * @param useIndex a boolean indicating whether each line should be started
    *    with an index.
    * @param indexPadWidth the padding width for index.
    * @param altIndex string to prefix if no index is used.
    * @param useASCII a boolean indicating whether each line should be ended
    *    with an ASCII representation of the bytes in that line.
    *
    * @return a hexadecimal representation of <code>data</code>.
    */
   public static String bytesToPrettyString(byte[] data, int columns,
                          boolean useIndex, int indexPadWidth, String altIndex,
                          boolean useASCII) {
      String result = "";
      String[] hexStrings = bytesToSpacedHexStrings(data,columns,3 * columns);
      String[] asciiStrings = bytesToASCIIStrings(data,columns,columns);
      for (int j = 0; j < hexStrings.length; j++) {
         if (useIndex) {
            String prefix = Integer.toHexString(j * columns).toUpperCase();
            result += pad(prefix,indexPadWidth,'0',LEFT) + ": ";
         } else {
            String prefix = j == 0 ? altIndex : "";
            result += pad(prefix,indexPadWidth,' ',LEFT) + " ";
         }
         result += hexStrings[j];
         if (useASCII) {
            result += " " + asciiStrings[j];
         }
         result += "\n";
      }
      return result;
   }
}

