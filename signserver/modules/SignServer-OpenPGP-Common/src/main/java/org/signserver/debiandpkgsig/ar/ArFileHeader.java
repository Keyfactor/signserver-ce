/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.debiandpkgsig.ar;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.apache.log4j.Logger;

/**
 * Represents and AR File Header and handles parsing and constructions of such.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ArFileHeader {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ParsedArFile.class);

    private static final String HEADER_END = "`\n";
    public static final int LENGTH = 60;

    private String fileIdentifier;
    private long fileModification;
    private int ownerID;
    private int groupID;
    private int fileMode;
    private int fileSize;

    public ArFileHeader(String fileIdentifier, long fileModification, int ownerID, int groupID, int fileMode, int fileSize) {
        this.fileIdentifier = fileIdentifier;
        this.fileModification = fileModification;
        this.ownerID = ownerID;
        this.groupID = groupID;
        this.fileMode = fileMode;
        this.fileSize = fileSize;
    }
    
    public static ArFileHeader parse(byte[] header) throws IOException {

        // Offset: 0, Length: 16, Name: File identifier, Format: ASCII
        final String fileIdentifierString = new String(header, 0, 16, StandardCharsets.US_ASCII);
        // Offset: 16, Length: 	12, Name: File modification timestamp, Format: Decimal
        final String fileModificationString = new String(header, 16, 12, StandardCharsets.US_ASCII);
        // Offset: 28, Length: 6, Name: Owner ID, Format: Decimal
        final String ownerIDString = new String(header, 28, 6, StandardCharsets.US_ASCII);
        // Offset: 34, Length: 6, Name: Group ID, Format: Decimal
        final String groupIDString = new String(header, 34, 6, StandardCharsets.US_ASCII);
        // Offset: 40, Length: 8, Name: File mode, Format: Octal
        final String fileModeString = new String(header, 40, 8, StandardCharsets.US_ASCII);
        // Offset: 48, Length: 10, Name: File size in bytes, Format: Decimal
        final String fileSizeString = new String(header, 48, 10, StandardCharsets.US_ASCII);
        // Offset: 58, Length: 2, Name: Ending characters, Format: 0x60 0x0A
        final String endCharacters = new String(header, 58, 2, StandardCharsets.US_ASCII);

        if (LOG.isDebugEnabled()) {
            LOG.debug("File header:\n"
                + "File identifier:             " + fileIdentifierString + "\n"
                + "File modification timestamp: " + fileModificationString + "\n"
                + "Owner ID:  " + ownerIDString + " Group ID: " + groupIDString + "\n"
                + "File mode: " + fileModeString + " File size in bytes: " + fileSizeString + " Ending characters: " + endCharacters);
        }

        if (!HEADER_END.equals(endCharacters)) {
            throw new IOException("Missing file header end characters");
        }

        final String fileIdentifier = stripTrailingSpaces(fileIdentifierString);
        final int fileModification = parseAsNumber("File modification timestamp", stripTrailingSpaces(fileModificationString));
        final int ownerID = parseAsNumber("Owner ID", stripTrailingSpaces(ownerIDString));
        final int groupID = parseAsNumber("Group ID", stripTrailingSpaces(groupIDString));
        final int fileMode = parseAsNumber("File mode", stripTrailingSpaces(fileModeString));
        final int fileSize = parseAsNumber("File size in bytes", stripTrailingSpaces(fileSizeString));

        return new ArFileHeader(fileIdentifier, fileModification, ownerID, groupID, fileMode, fileSize);
    }
    
    public byte[] getEncoded() throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream(60);
        
        bout.write(paddedBytes(16, fileIdentifier));
        bout.write(paddedBytes(12, fileModification));
        bout.write(paddedBytes(6, ownerID));
        bout.write(paddedBytes(6, groupID));
        bout.write(paddedBytes(8, fileMode));
        bout.write(paddedBytes(10, fileSize));
        bout.write(paddedBytes(2, HEADER_END));

        if (bout.size() != LENGTH) {
            throw new IOException("Incorrect header length encoded: " + bout.size());
        }
        return bout.toByteArray();
    }

    public String getFileIdentifier() {
        return fileIdentifier;
    }

    public void setFileIdentifier(String fileIdentifier) {
        this.fileIdentifier = fileIdentifier;
    }

    public long getFileModification() {
        return fileModification;
    }

    public void setFileModification(int fileModification) {
        this.fileModification = fileModification;
    }

    public int getOwnerID() {
        return ownerID;
    }

    public void setOwnerID(int ownerID) {
        this.ownerID = ownerID;
    }

    public int getGroupID() {
        return groupID;
    }

    public void setGroupID(int groupID) {
        this.groupID = groupID;
    }

    public int getFileMode() {
        return fileMode;
    }

    public void setFileMode(int fileMode) {
        this.fileMode = fileMode;
    }

    public int getFileSize() {
        return fileSize;
    }

    public void setFileSize(int fileSize) {
        this.fileSize = fileSize;
    }

    @Override
    public String toString() {
        return "ArFileHeader{" + "fileIdentifier=" + fileIdentifier + ", fileModification=" + fileModification + ", ownerID=" + ownerID + ", groupID=" + groupID + ", fileMode=" + fileMode + ", fileSize=" + fileSize + '}';
    }

    private static String stripTrailingSpaces(String value) {
        int last = lastIndexOfNonSpace(value);
        if (last < 0) {
            return value;
        } else {
            return value.substring(0, last);
        }
    }

    private static int lastIndexOfNonSpace(String value) {
        int length = value.length();
        int pos = length;
        while (pos >= 0) {
            char ch = value.charAt(pos - 1);
            if (ch != ' ') {
                break;
            }
            pos--;
        }
        return pos;
    }

    private static int parseAsNumber(String fieldName, String value) throws IOException {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            throw new IOException("Unable to parse " + fieldName);
        }
    }
    
    private byte[] paddedBytes(int length, String string) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) 0x20);
        byte[] stringBytes = string.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(stringBytes, 0, result, 0, stringBytes.length);
        return result;
    }
    
    private byte[] paddedBytes(int length, int number) {
        return paddedBytes(length, String.valueOf(number));
    }
    
    private byte[] paddedBytes(int length, long number) {
        return paddedBytes(length, String.valueOf(number));
    }
}
