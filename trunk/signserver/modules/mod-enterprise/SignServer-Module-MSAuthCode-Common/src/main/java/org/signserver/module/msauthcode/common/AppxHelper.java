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
package org.signserver.module.msauthcode.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.signserver.common.IllegalRequestException;
import java.util.Arrays;
import java.io.RandomAccessFile;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.zip.Deflater;
import java.util.zip.CRC32;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.BufferUnderflowException;
import java.util.List;
import java.util.ArrayList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import javax.xml.transform.OutputKeys;
import java.util.zip.Inflater;
import java.nio.charset.StandardCharsets;
import java.util.zip.DataFormatException;
import org.apache.log4j.Logger;


/**
 * Helper class for APPX packages.  
 *
 * Partly based on/inspired by implementation from fb-util-for-appx (https://github.com/facebook/fb-util-for-appx)
 * @author Selwyn Oh
 * @version $Id$
 */
public class AppxHelper {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AppxHelper.class);

    // ZIP64 spec constants
    private static final int ZIP64_EOCD_HDR_SIZE = 22;
    private static final int ZIP64_LOCAL_HEADER_MAGIC = 0x04034b50;
    private static final int ZIP64_DATA_DESCRIPTOR_LONG_LEN = 20;
    private static final int ZIP64_DATA_DESCRIPTOR_SHORT_LEN = 12;
    private static final int ZIP64_DATA_DESCRIPTOR_MAGIC = 0x08074b50;
    private static final int ZIP64_CENTRAL_DIR_MAGIC = 0x02014b50;
    private static final int ZIP64_EOCD_LOCATOR_SIZE = 20;
    private static final int ZIP64_EOCD_LOCATOR_MAGIC = 0x07064b50;
    private static final int ZIP64_EOCD_RECORD_EFFECTIVE_SIZE = 52;
    private static final int ZIP64_EOCD_RECORD_SIGNATURE = 0x06064b50;
    private static final int ZIP64_CENTRAL_DIR_MINSIZE = 46;
    private static final int ZIP64_EXTENSIBLE_DATA_SIZE = 42;
    private static final int ZIP64_LOCAL_DIRECTORY_MAGIC = 0x02014B50;
    private static final short ZIP64_VERSION_MADE_45 = 45;
    private static final short ZIP64_VERSION_NEEDED_45 = 45;
    private static final short ZIP64_VERSION_NEEDED_20 = 20;
    private static final short ZIP64_GENERAL_PURPOSE_8 = 8;
    private static final short ZIP64_GENERAL_PURPOSE_0 = 0;
    private static final short ZIP64_LOCAL_HEADER_SIZE = 26;
    private static final short ZIP64_DEFLATE_COMPRESSION = 8;

    private static final short SHORT_ZERO = 0;
    private static final int INT_ZERO = 0;

    private static final String CONTENT_TYPES_FILENAME = "[Content_Types].xml";
    private static final String APPX_BLOCKMAP_FILENAME = "AppxBlockMap.xml";
    private static final String APPX_SIGNATURE_FILENAME = "AppxSignature.p7x";

    // Appx digest signatures
    private static final byte[] APPX_DIGEST_SIGNATURE = new byte[] {(byte) 0x41, (byte) 0x50, (byte) 0x50, (byte) 0x58};
    private static final byte[] APPX_AXPC_SIGNATURE = new byte[] {(byte) 0x41, (byte) 0x58, (byte) 0x50, (byte) 0x43};
    private static final byte[] APPX_AXCD_SIGNATURE = new byte[] {(byte) 0x41, (byte) 0x58, (byte) 0x43, (byte) 0x44};
    private static final byte[] APPX_AXCT_SIGNATURE = new byte[] {(byte) 0x41, (byte) 0x58, (byte) 0x43, (byte) 0x54};
    private static final byte[] APPX_AXBM_SIGNATURE = new byte[] {(byte) 0x41, (byte) 0x58, (byte) 0x42, (byte) 0x4d};
    private static final byte[] APPX_AXCI_SIGNATURE = new byte[] {(byte) 0x41, (byte) 0x58, (byte) 0x43, (byte) 0x49};

    // AppxSignature.p7x file signature
    private static final byte[] P7X_SIGNATURE = new byte[] {(byte) 0x50, (byte) 0x4b, (byte) 0x43, (byte) 0x58};

    // AppxSignature.p7x last modified time and date. Hardcoded to make signatures deterministic.
    private static final short SIG_FILE_TIME = (short)0x250a;
    private static final short SIG_FILE_DATE = (short)0x4f67;
    
    /**
     * Process the input file and produce the data that should be signed.
     *
     * @param rafInput file
     * @param rafOutput file
     * @param digestAlgorithm for hashes
     * @param cdoNewCentralDirOffset new central directory offset
     * @param baosReconstructCentralDirectoryRecords stream for receiving the reconstructed central directory records
     * @param eocdValues
     * @return the data to be signed
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws IllegalRequestException 
     */
    public static byte[] produceSignatureInput(RandomAccessFile rafInput, RandomAccessFile rafOutput, String digestAlgorithm, CentralDirectoryOffset cdoNewCentralDirOffset,
        ByteArrayOutputStream baosReconstructCentralDirectoryRecords, EocdField eocdValues) throws NoSuchAlgorithmException, IOException, IllegalRequestException {

        rafInput.seek(0);

        final long fileLength = rafInput.length();
        long scanOffset = fileLength - ZIP64_EOCD_HDR_SIZE;


        // File too small to be a valid zip64 file
        if (scanOffset < 0) {
            throw new IllegalRequestException ("Not a valid Appx file.");
        }

        //Subtract max comment length
        long stopOffset = scanOffset - 65536;

        //File size smaller than max comment length + EOCD header size
        if (stopOffset < 0) {
            stopOffset = 0;
        }

        //
        // Parse EOCD Header
        //
        final int END_HEADER_MAGIC = 0x06054b50;
        while (true) {
            rafInput.seek(scanOffset);
            if (Integer.reverseBytes(rafInput.readInt()) == END_HEADER_MAGIC) {
                break;
            }
            scanOffset--;
            if (scanOffset < stopOffset) {
                throw new IllegalRequestException("EOCD not found. Invalid file format.");
            }
        }
        
        long zip64EocdRecordOffset;
        long lngCDOffset = -1;

        // The ZIP64 EOCD locator is located 20 bytes before the EOCD signature
        // If the offset of the EOCD locator is > 20, continue to search for the ZIP64 EOCD
        if (scanOffset > ZIP64_EOCD_LOCATOR_SIZE) {
            rafInput.seek(scanOffset - ZIP64_EOCD_LOCATOR_SIZE);
            if (Integer.reverseBytes(rafInput.readInt()) == ZIP64_EOCD_LOCATOR_MAGIC) {
                final byte[] zipEocdLocator = new byte[ZIP64_EOCD_LOCATOR_SIZE - 4];

                rafInput.readFully(zipEocdLocator);
                final ByteBuffer buf = ByteBuffer.wrap(zipEocdLocator).order(ByteOrder.LITTLE_ENDIAN);
                final int diskWithCentralDir = buf.getInt();
                zip64EocdRecordOffset = buf.getLong();
                final int numDisks = buf.getInt();

                rafInput.seek(zip64EocdRecordOffset);

                if (Integer.reverseBytes(rafInput.readInt())!=  ZIP64_EOCD_RECORD_SIGNATURE) {
                    throw new IllegalRequestException("Failed to find EOCD record signature");
                }

                final byte[] zip64Eocd = new byte[ZIP64_EOCD_RECORD_EFFECTIVE_SIZE];
                rafInput.readFully(zip64Eocd);

                final ByteBuffer bufEocd = ByteBuffer.wrap(zip64Eocd).order(ByteOrder.LITTLE_ENDIAN);
                try {
                    eocdValues.longSizeOfEocd = bufEocd.getLong();
                    eocdValues.shortVerMade = bufEocd.getShort();
                    eocdValues.shortVerNeeded = bufEocd.getShort();
                    eocdValues.intDiskNum = bufEocd.getInt();
                    eocdValues.intDiskCd = bufEocd.getInt();
                    eocdValues.longNumEntries = bufEocd.getLong();
                    eocdValues.longTotalNumEntries = bufEocd.getLong();
                    eocdValues.longCdSize = bufEocd.getLong();
                    eocdValues.longCentralDirOffset = bufEocd.getLong();
                    lngCDOffset = eocdValues.longCentralDirOffset;

                    if (Integer.reverseBytes(rafInput.readInt()) == ZIP64_EOCD_LOCATOR_MAGIC) {
                        final byte[] byteArrZipExtensibleData = new byte[ZIP64_EXTENSIBLE_DATA_SIZE - 4];
                        rafInput.readFully(byteArrZipExtensibleData);
                        final ByteBuffer bufZipEx = ByteBuffer.wrap(byteArrZipExtensibleData).order(ByteOrder.LITTLE_ENDIAN);

                        eocdValues.intZipExField1 = bufZipEx.getInt();      // 0x00000000
                        eocdValues.longEocdOffset = bufZipEx.getLong();     // EOCD offset
                        eocdValues.intZipExField3 = bufZipEx.getInt();      // 0x01000000
                        eocdValues.intEocdMagic = bufZipEx.getInt();        // 0x504b0506
                        eocdValues.intSignedAppxFlag = bufZipEx.getInt();   // 0xffffffff (unsigned) 0x00000000 (signed)
                        eocdValues.intZipExField6 = bufZipEx.getInt();      // 0xffffffff
                        eocdValues.intZipExField7 = bufZipEx.getInt();      // 0xffffffff
                        eocdValues.intZipExField8 = bufZipEx.getInt();      // 0xffffffff
                        eocdValues.shortZipExEnd = bufZipEx.getShort();     // 0x0000
                    }
                } catch (BufferUnderflowException bue) {
                    throw new IllegalRequestException("Failed to find Central Directory offset" , bue);
                }
            }
        } else {
            throw new IllegalRequestException("Invalid Appx file");
        }

        if (lngCDOffset == -1) {
            throw new IllegalRequestException("Unable to parse Appx file");
        }

        // Read Central Directory            
        rafInput.seek(lngCDOffset);

        final byte[] byteArrCentralDirEntry = new byte[ZIP64_CENTRAL_DIR_MINSIZE - 4];

        int intCntEntries = 0;
        int intContentTypesIndex = -1; //index of [Content_Types].xml entry
        

        final List<CentralDirectoryEntry> listCentralDirEntries = new ArrayList<>();
        final List<LocalRecord> listLocalRecordEntries = new ArrayList<>();
        final ByteArrayOutputStream baosPreContentTypesEntries = new ByteArrayOutputStream();
        long longOriginalEndOffset = -1;

        byte[] byteArrContentTypesFileData = new byte[0];
        byte[] byteArrBlockMapFileData = new byte[0];

        while(true) {
            if (Integer.reverseBytes(rafInput.readInt()) == ZIP64_CENTRAL_DIR_MAGIC) {
                rafInput.readFully(byteArrCentralDirEntry);
                ByteBuffer byteBufCentralDirEntry = ByteBuffer.wrap(byteArrCentralDirEntry).order(ByteOrder.LITTLE_ENDIAN);
                CentralDirectoryEntry cdEntry = new CentralDirectoryEntry();

                try {
                    short shortVerMade = byteBufCentralDirEntry.getShort();
                    short shortVerNeeded = byteBufCentralDirEntry.getShort();
                    short shortGenPurpose = byteBufCentralDirEntry.getShort();
                    short shortCompressMethod = byteBufCentralDirEntry.getShort();
                    short shortLastModTime = byteBufCentralDirEntry.getShort();
                    short shortLastModDate = byteBufCentralDirEntry.getShort();
                    int intCrc32 = byteBufCentralDirEntry.getInt();
                    int intCompressedSize = byteBufCentralDirEntry.getInt();
                    int intUncompressedSize = byteBufCentralDirEntry.getInt();
                    short shortFilenameLen = byteBufCentralDirEntry.getShort();
                    short shortExtraFieldLen = byteBufCentralDirEntry.getShort();
                    short shortFileCommentLen = byteBufCentralDirEntry.getShort();
                    short shortDiskNumStart = byteBufCentralDirEntry.getShort();
                    short shortInternalFileAttr = byteBufCentralDirEntry.getShort();
                    int intExternalFileAttr = byteBufCentralDirEntry.getInt();
                    int intLocalHeaderOffset = byteBufCentralDirEntry.getInt();

                    cdEntry.setShortVerMade(shortVerMade);
                    cdEntry.setShortVerNeeded(shortVerNeeded);
                    cdEntry.setShortGenPurpose(shortGenPurpose);
                    cdEntry.setShortCompressMethod(shortCompressMethod);
                    cdEntry.setShortLastModTime(shortLastModTime);
                    cdEntry.setShortLastModDate(shortLastModDate);
                    cdEntry.setIntCrc32(intCrc32);
                    cdEntry.setIntCompressedSize(intCompressedSize);
                    cdEntry.setIntUncompressedSize(intUncompressedSize);
                    cdEntry.setShortFilenameLen(shortFilenameLen);
                    cdEntry.setShortExtraFieldLen(shortExtraFieldLen);
                    cdEntry.setShortFileCommentLen(shortFileCommentLen);
                    cdEntry.setShortDiskNumStart(shortDiskNumStart);
                    cdEntry.setShortInternalFileAttr(shortInternalFileAttr);
                    cdEntry.setIntExternalFileAttr(intExternalFileAttr);
                    cdEntry.setIntLocalHeaderOffset(intLocalHeaderOffset);

                    byte[] byteArrFilename = new byte[(int)shortFilenameLen];

                    rafInput.readFully(byteArrFilename);
                    cdEntry.setByteArrFilename(byteArrFilename);

                    byte[] byteArrExtraField = new byte[(int)shortExtraFieldLen];
                    if (shortExtraFieldLen > 0) {
                        
                        rafInput.readFully(byteArrExtraField);
                        cdEntry.setByteArrExtraField(byteArrExtraField);
                    }
                    byte[] byteArrFileComment = new byte[(int)shortFileCommentLen];
                    if (shortFileCommentLen > 0) {
                        
                        rafInput.readFully(byteArrFileComment);
                        cdEntry.setByteArrFileComment(byteArrFileComment);
                    }

                    listCentralDirEntries.add(cdEntry);

                    if (Arrays.equals(APPX_SIGNATURE_FILENAME.getBytes(StandardCharsets.UTF_8), byteArrFilename)) {
                        throw new IllegalRequestException("Appx file is already signed. Re-signing is not supported.");
                    }

                    final boolean contentTypes;
                    if (Arrays.equals(CONTENT_TYPES_FILENAME.getBytes(StandardCharsets.UTF_8), byteArrFilename)) {
                        contentTypes = true;
                        intContentTypesIndex = intCntEntries;
                    } else {
                        contentTypes = false;
                    }

                    final long longLocalRecOffset = cdEntry.getLongLocalHeaderOffset();
                    final long longLocalRecSize = cdEntry.getLongCompressedSize();
                    final long longLocalRecUncompressedSize = cdEntry.getLongUncompressedSize();
                    final long longCurrentOffset = rafInput.getFilePointer();

                    // Process local record
                    final LocalRecord lrUpdated = processLocalRec(rafInput, rafOutput, cdEntry, longLocalRecOffset, longLocalRecSize);
                    listLocalRecordEntries.add(lrUpdated);

                    if (contentTypes) {
                        byteArrContentTypesFileData = lrUpdated.getByteArrInflatedRecord();
                    }

                    if (Arrays.equals(APPX_BLOCKMAP_FILENAME.getBytes(StandardCharsets.UTF_8),byteArrFilename)) {
                        byteArrBlockMapFileData = lrUpdated.getByteArrInflatedRecord();
                    }

                    longOriginalEndOffset = lrUpdated.getLongEndOffset();

                    intCntEntries++;
                } catch (BufferUnderflowException bue) {
                    throw new IllegalRequestException ("Failed to read Central Directory Entry" , bue);
                }
            } else {
                break;
            }
        }

        // Reconstruct central directory entries
        for (int intCntDir = 0; intCntDir < intCntEntries; intCntDir++) {
            final CentralDirectoryEntry cdeEntry = listCentralDirEntries.get(intCntDir);
            final LocalRecord lrRec = listLocalRecordEntries.get(intCntDir);
            final boolean contentTypes = intContentTypesIndex == intCntDir;

            int intUncompressedSize;
            int intCompressedSize;
            int intCrc32;

            final short shortGenPurposeFlag = lrRec.getShortGenPurpose();
            byte[] byteArrModifiedContentTypesRecord = lrRec.getByteArrModifiedRecord();

            if (contentTypes) {
                if (byteArrModifiedContentTypesRecord.length > 0) {
                    intUncompressedSize = (int) lrRec.getLongUpdatedUncompressedSize();
                    intCompressedSize = (int) lrRec.getLongUpdatedCompressedSize();
                    intCrc32 = (int) lrRec.getLongUpdatedCrc32();
                } else {
                    intUncompressedSize = (int) cdeEntry.getLongUncompressedSize();
                    intCompressedSize = (int) cdeEntry.getLongCompressedSize();
                    intCrc32 = cdeEntry.getIntCrc32();
                }
            } else {
                intUncompressedSize = (int) cdeEntry.getLongUncompressedSize();
                intCompressedSize = (int) cdeEntry.getLongCompressedSize();
                intCrc32 = cdeEntry.getIntCrc32();
            }

            baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(ZIP64_CENTRAL_DIR_MAGIC));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortVerMade()));
            
            // For [Content_Types].xml, always set the version needed to 2.0 and the general purpose flag to 0 (no data descriptor)
            if (contentTypes) {
                baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(ZIP64_VERSION_NEEDED_20));
                baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(ZIP64_GENERAL_PURPOSE_0)); //gen purpose 0
            } else {
                // For all other files, set version needed based on the original value of the general purpose flag
                if (shortGenPurposeFlag == ZIP64_GENERAL_PURPOSE_8) {
                    baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(ZIP64_VERSION_NEEDED_45));
                    baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(ZIP64_GENERAL_PURPOSE_8));
                } else {
                    baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(ZIP64_VERSION_NEEDED_20));
                    baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(ZIP64_GENERAL_PURPOSE_0));
                }
            }
            
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortCompressMethod()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortLastModTime()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortLastModDate()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(intCrc32));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(intCompressedSize));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(intUncompressedSize));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortFilenameLen()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian((short) 0)); //Remove extra field
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortFileCommentLen()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortDiskNumStart()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortInternalFileAttr()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(cdeEntry.getIntExternalFileAttr()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian((int) cdeEntry.getLongNewLocalHeaderOffset())); // Local header offset does not change for [Content_Types].xml
            baosReconstructCentralDirectoryRecords.write(cdeEntry.getByteArrFilename());
            baosReconstructCentralDirectoryRecords.write(cdeEntry.getByteArrFileComment());
        }

        final byte[] byteArrReconstructedCentralDirRecords = baosReconstructCentralDirectoryRecords.toByteArray();

        // New Central Directory Offset
        final long longNewCentralDirOffset = rafOutput.getFilePointer();
        cdoNewCentralDirOffset.setCentralDirOffset(longNewCentralDirOffset);
        rafOutput.write(byteArrReconstructedCentralDirRecords);

        // New EOCD Offset
        final long longNewEocdOffset = rafOutput.getFilePointer();
        final byte[] byteArrEocd = eocdValues.getEocdInitial((long)byteArrReconstructedCentralDirRecords.length, longNewCentralDirOffset, longNewEocdOffset);
        rafOutput.write(byteArrEocd);    

        final ByteArrayOutputStream digestBytes = new ByteArrayOutputStream();
        digestBytes.write(APPX_DIGEST_SIGNATURE);
        digestBytes.write(APPX_AXPC_SIGNATURE);

        try {
            // Digest Local Records
            rafOutput.seek(0);
            long readCount = 0;
            long readLen;
            final byte[] readBuf = new byte[4096];
            final MessageDigest mdZipRec = MessageDigest.getInstance(digestAlgorithm);
                
            while (readCount < longNewCentralDirOffset) {
                readLen = Math.min(longNewCentralDirOffset - readCount, 4096);
                rafOutput.read(readBuf);
                mdZipRec.update(readBuf, 0, (int) readLen);
                readCount += readLen;
            }
            byte[] byteArrZipRecDigest = mdZipRec.digest();

            // Digest Central Directory to EOF
            rafOutput.seek(longNewCentralDirOffset);
            int intCdRead = 0;
            byte[] byteCdBuf = new byte[4096];
            final MessageDigest mdCdDigest = MessageDigest.getInstance(digestAlgorithm);

            while (-1 != (intCdRead = rafOutput.read(byteCdBuf))) {
                mdCdDigest.update(byteCdBuf,0,intCdRead);
            }

            byte[] mdCdDigestNew = mdCdDigest.digest();

            digestBytes.write(byteArrZipRecDigest);
            digestBytes.write(APPX_AXCD_SIGNATURE);
            digestBytes.write(mdCdDigestNew);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalRequestException("Digest Alogorithm not supported", ex);
        }

        byte[] appxBlockMapDigest = new byte[0];
        byte[] contentTypesDigest = new byte[0];

        int direntrysize = 0;
        long filerecordsize = 0;

        // Digest inflated AppxBlockMap.xml and [Content_Types].xml
        if (byteArrBlockMapFileData.length > 0) {
            try {
                final MessageDigest mdpart = MessageDigest.getInstance(digestAlgorithm);          
                InputStream inBlockMap = new ByteArrayInputStream(byteArrBlockMapFileData);
                appxBlockMapDigest = digest(inBlockMap, mdpart);
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalRequestException("Log digest algorithm not supported", ex);
            }
        } else {
            throw new IllegalRequestException("Invalid APPX file. Missing AppxBlockMap.xml data.");
        }

        if (byteArrContentTypesFileData.length > 0) {
            try {
                final MessageDigest mdpart = MessageDigest.getInstance(digestAlgorithm);
                InputStream inContentTypes = new ByteArrayInputStream(byteArrContentTypesFileData);
                contentTypesDigest = digest(inContentTypes, mdpart);
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalRequestException("Log digest algorithm not supported", ex);
            }
        } else {
            throw new IllegalRequestException("Invalid Appx file. Missing [Content_Types].xml.");
        }

        digestBytes.write(APPX_AXCT_SIGNATURE);
        digestBytes.write(contentTypesDigest);
        digestBytes.write(APPX_AXBM_SIGNATURE);
        digestBytes.write(appxBlockMapDigest);
        digestBytes.write(APPX_AXCI_SIGNATURE);

        final byte[] finalDigest = digestBytes.toByteArray();

        // Pad with 0x00 if digest is < 184 bytes;
        final ByteArrayOutputStream baosPad = new ByteArrayOutputStream();
        baosPad.write(finalDigest);
        if (finalDigest.length < 184) {
            for (int cnt = 0; cnt < 184 - finalDigest.length; cnt++) {
                baosPad.write(0x00);
            }
        }

        final byte[] paddedDigest = baosPad.toByteArray();

        return paddedDigest;
    }

    /**
     * Assemble the final file containing the signature.
     *
     * @param rafOutput file to write to
     * @param byteArrSignedData the signature
     * @param longNewCentralDirOffset new central directory offset
     * @param byteArrReconstructedCentralDirRecords reconstructed central directory records bytes
     * @param eocdValues
     * @throws IOException 
     */
    public static void assemble(RandomAccessFile rafOutput, byte[] byteArrSignedData, long longNewCentralDirOffset, byte[] byteArrReconstructedCentralDirRecords, EocdField eocdValues) throws IOException {
        try { 

            final CMSSignedData signedData = new CMSSignedData(byteArrSignedData);
            final byte[] signedbytes = signedData.toASN1Structure().getEncoded("DER");

            final ByteArrayOutputStream appxSignatureStream = new ByteArrayOutputStream();
            appxSignatureStream.write(P7X_SIGNATURE);
            appxSignatureStream.write(signedbytes);
            byte[] appxSignatureBytes = appxSignatureStream.toByteArray();

            final ByteArrayOutputStream baosDeflate = new ByteArrayOutputStream();
            final Deflater dflater = new Deflater(9, true);
            dflater.setInput(appxSignatureBytes);
            final byte[] dbuff = new byte[1024];
            dflater.finish();
            while (!dflater.finished()) {
                int n = dflater.deflate(dbuff);
                baosDeflate.write(dbuff, 0, n);
            }
            final byte[] deflatedSig = baosDeflate.toByteArray();
            dflater.end();

            // CRC32 checksum
            CRC32 crc = new CRC32();
            crc.update(appxSignatureBytes);
            long crc32val = crc.getValue();

            // Uncompressed Size
            int intUncompressedSize = appxSignatureBytes.length;
            int intCompressedSize = deflatedSig.length;

            //
            // Construct AppxSignature.p7x Local Record
            //
            final ByteArrayOutputStream baosHeader = new ByteArrayOutputStream();

            final String strSanitizedFilename = "AppxSignature.p7x";
            final byte[] sanitizedFilenameBytes = strSanitizedFilename.getBytes(StandardCharsets.UTF_8);
            final short shortFilenameSize = (short) sanitizedFilenameBytes.length;

            //check CRC value
            final ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
            buffer.putLong(crc32val);

            baosHeader.write(ZipUtil.intToLittleEndian(ZIP64_LOCAL_HEADER_MAGIC));
            baosHeader.write(ZipUtil.shortToLittleEndian(ZIP64_VERSION_NEEDED_20));
            baosHeader.write(ZipUtil.shortToLittleEndian(SHORT_ZERO));
            baosHeader.write(ZipUtil.shortToLittleEndian(ZIP64_DEFLATE_COMPRESSION));
            baosHeader.write(ZipUtil.shortToLittleEndian(SIG_FILE_TIME));
            baosHeader.write(ZipUtil.shortToLittleEndian(SIG_FILE_DATE));

            final int intCrc = (int) crc32val;
            
            baosHeader.write(ZipUtil.intToLittleEndian(intCrc));
            baosHeader.write(ZipUtil.intToLittleEndian(intCompressedSize));
            baosHeader.write(ZipUtil.intToLittleEndian(intUncompressedSize));
            baosHeader.write(ZipUtil.shortToLittleEndian(shortFilenameSize));
            baosHeader.write(ZipUtil.shortToLittleEndian(SHORT_ZERO));

            baosHeader.write(sanitizedFilenameBytes);
            baosHeader.write(deflatedSig);
            
            final byte[] appxSigRecord = baosHeader.toByteArray();

            // Write AppxSignature.p7x Local Record
            rafOutput.seek(longNewCentralDirOffset);
            rafOutput.write(appxSigRecord);

            // Final Central Directory offset
            final long longFinalCentralDirectoryOffset = rafOutput.getFilePointer();

            // Write Central Directory
            rafOutput.write(byteArrReconstructedCentralDirRecords);

            //Write AppxSignature.p7x Directory Entry
            final ByteArrayOutputStream baosDirectoryEntry = new ByteArrayOutputStream();

            baosDirectoryEntry.write(ZipUtil.intToLittleEndian(ZIP64_LOCAL_DIRECTORY_MAGIC));
            baosDirectoryEntry.write(ZipUtil.shortToLittleEndian(ZIP64_VERSION_MADE_45));
            baosDirectoryEntry.write(ZipUtil.shortToLittleEndian(ZIP64_VERSION_NEEDED_20));
            baosDirectoryEntry.write(ZipUtil.shortToLittleEndian(SHORT_ZERO));
            baosDirectoryEntry.write(ZipUtil.shortToLittleEndian(ZIP64_DEFLATE_COMPRESSION));
            baosDirectoryEntry.write(ZipUtil.shortToLittleEndian(SIG_FILE_TIME));
            baosDirectoryEntry.write(ZipUtil.shortToLittleEndian(SIG_FILE_DATE));
            baosDirectoryEntry.write(ZipUtil.intToLittleEndian(intCrc));
            baosDirectoryEntry.write(ZipUtil.intToLittleEndian(intCompressedSize));
            baosDirectoryEntry.write(ZipUtil.intToLittleEndian(intUncompressedSize));
            baosDirectoryEntry.write(ZipUtil.shortToLittleEndian(shortFilenameSize));
            baosDirectoryEntry.write(ZipUtil.shortToLittleEndian(SHORT_ZERO));
            baosDirectoryEntry.write(ZipUtil.shortToLittleEndian(SHORT_ZERO));
            baosDirectoryEntry.write(ZipUtil.shortToLittleEndian(SHORT_ZERO));
            baosDirectoryEntry.write(ZipUtil.shortToLittleEndian(SHORT_ZERO));
            baosDirectoryEntry.write(ZipUtil.intToLittleEndian(INT_ZERO));

            baosDirectoryEntry.write(ZipUtil.intToLittleEndian((int)longNewCentralDirOffset)); //Local Header Offset is old central directory offset
            
            baosDirectoryEntry.write(sanitizedFilenameBytes);

            final byte[] baosSigDirEntry = baosDirectoryEntry.toByteArray();

            rafOutput.write(baosSigDirEntry); //Write signature directory entry

            final long longFinalEocdOffset = rafOutput.getFilePointer();

            // Write EOCD
            final int intNewCdSize = byteArrReconstructedCentralDirRecords.length + baosSigDirEntry.length;
            final byte[] byteArrFinalEocd = eocdValues.getEocdFinal(intNewCdSize, longFinalCentralDirectoryOffset, longFinalEocdOffset);

            rafOutput.write(byteArrFinalEocd);
            rafOutput.close();
        } catch (CMSException e) {
            throw new IllegalArgumentException("Signature output is not a CMSSignedData structure", e);
        }
    }

    /**
     * Process the input file, creating a new output file with the signature file
     * stripped and calculate the digest.
     *
     * @param originalFile to process
     * @param newFile (could be temporary) file to buffer the file without the signature and that should be digested
     * @param digestAlgorithm to use for digesting
     * @return the digest value
     * @throws IOException in case the files can not be read or written
     * @throws IllegalRequestException for incorrect files
     */
    public static byte[] calculateDigestForVerification(RandomAccessFile originalFile, RandomAccessFile newFile, String digestAlgorithm) throws IOException, IllegalRequestException {
        LOG.debug(">calculateDigestForVerification");

        // EOCD field data
        final EocdField eocdValues = new EocdField();

        originalFile.seek(0);

        final long fileLength = originalFile.length();
        long scanOffset = fileLength - ZIP64_EOCD_HDR_SIZE;

        // File too small to be a valid zip64 file
        if (scanOffset < 0) {
            throw new IllegalRequestException("Not a valid Appx file.");
        }

        // Subtract max comment length
        long stopOffset = scanOffset - 65536;

        // File size smaller than max comment length + EOCD header size
        if (stopOffset < 0) {
            stopOffset = 0;
        }

        //
        // Parse EOCD Header
        //
        final int END_HEADER_MAGIC = 0x06054b50;
        while (true) {
            originalFile.seek(scanOffset);
            if (Integer.reverseBytes(originalFile.readInt()) == END_HEADER_MAGIC) {
                break;
            }
            scanOffset--;

            if (scanOffset < stopOffset) {
                throw new IllegalRequestException("EOCD not found. Invalid file format.");
            }
        }
                    
        long zip64EocdRecordOffset;
        long lngCDOffset = -1;

        // The ZIP64 EOCD locator is located 20 bytes before the EOCD signature
        // If the offset of the EOCD locator is > 20, continue to search for the ZIP64 EOCD
        if (scanOffset > ZIP64_EOCD_LOCATOR_SIZE) {
            originalFile.seek(scanOffset - ZIP64_EOCD_LOCATOR_SIZE);
            if (Integer.reverseBytes(originalFile.readInt()) == ZIP64_EOCD_LOCATOR_MAGIC) {
                byte[] zipEocdLocator = new byte[ZIP64_EOCD_LOCATOR_SIZE - 4];

                originalFile.readFully(zipEocdLocator);
                ByteBuffer  buf = ByteBuffer.wrap(zipEocdLocator).order(ByteOrder.LITTLE_ENDIAN);
                final int diskWithCentralDir = buf.getInt();
                zip64EocdRecordOffset = buf.getLong();
                final int numDisks = buf.getInt();

                originalFile.seek(zip64EocdRecordOffset);

                if (Integer.reverseBytes(originalFile.readInt())!=  ZIP64_EOCD_RECORD_SIGNATURE) {
                    throw new IllegalRequestException("Failed to find EOCD record signature");
                }

                byte[] zip64Eocd = new byte[ZIP64_EOCD_RECORD_EFFECTIVE_SIZE];
                originalFile.readFully(zip64Eocd);

                ByteBuffer bufEocd = ByteBuffer.wrap(zip64Eocd).order(ByteOrder.LITTLE_ENDIAN);
                try {
                    eocdValues.longSizeOfEocd = bufEocd.getLong();
                    eocdValues.shortVerMade = bufEocd.getShort();
                    eocdValues.shortVerNeeded = bufEocd.getShort();
                    eocdValues.intDiskNum = bufEocd.getInt();
                    eocdValues.intDiskCd = bufEocd.getInt();
                    eocdValues.longNumEntries = bufEocd.getLong();
                    eocdValues.longTotalNumEntries = bufEocd.getLong();
                    eocdValues.longCdSize = bufEocd.getLong();
                    eocdValues.longCentralDirOffset = bufEocd.getLong();
                    lngCDOffset = eocdValues.longCentralDirOffset;

                    if (Integer.reverseBytes(originalFile.readInt()) == ZIP64_EOCD_LOCATOR_MAGIC) {
                        byte[] byteArrZipExtensibleData = new byte[ZIP64_EXTENSIBLE_DATA_SIZE - 4];
                        originalFile.readFully(byteArrZipExtensibleData);
                        ByteBuffer bufZipEx = ByteBuffer.wrap(byteArrZipExtensibleData).order(ByteOrder.LITTLE_ENDIAN);

                        eocdValues.intZipExField1 = bufZipEx.getInt();      // 0x00000000
                        eocdValues.longEocdOffset = bufZipEx.getLong();     // EOCD offset
                        eocdValues.intZipExField3 = bufZipEx.getInt();      // 0x01000000
                        eocdValues.intEocdMagic = bufZipEx.getInt();        // 0x504b0506
                        eocdValues.intSignedAppxFlag = bufZipEx.getInt();   // 0xffffffff (unsigned) 0x00000000 (signed)
                        eocdValues.intZipExField6 = bufZipEx.getInt();      // 0xffffffff
                        eocdValues.intZipExField7 = bufZipEx.getInt();      // 0xffffffff
                        eocdValues.intZipExField8 = bufZipEx.getInt();      // 0xffffffff
                        eocdValues.shortZipExEnd = bufZipEx.getShort();     // 0x0000
                    }
                } catch (BufferUnderflowException bue) {
                    throw new IllegalRequestException("Failed to find Central Directory offset" , bue);
                }
            }
        } else {
            throw new IllegalRequestException("Invalid Appx file");
        }

        if (lngCDOffset == -1) {
            throw new IllegalRequestException("Unable to parse Appx file");
        }

        // Read Central Directory            
        originalFile.seek(lngCDOffset);

        byte[] byteArrCentralDirEntry = new byte[ZIP64_CENTRAL_DIR_MINSIZE - 4];

        int intCntEntries = 0;
        int intContentTypesIndex = -1; //index of [Content_Types].xml entry

        List<CentralDirectoryEntry> listCentralDirEntries = new ArrayList<>();
        ByteArrayOutputStream baosPreContentTypesEntries = new ByteArrayOutputStream();
        long longOriginalEndOffset = -1;
        AppxHelper.LocalRecord lrUpdated = new AppxHelper.LocalRecord();
        long longLocalRecOffset;

        byte[] byteArrContentTypesFileData = new byte[0];
        byte[] byteArrBlockMapFileData = new byte[0];
        long longAppxSignatureOffset = -1;
        long longNextOffset = -1;
        int intAppxSignatureIndex = -1; 

        while (true) {
            if (Integer.reverseBytes(originalFile.readInt()) == ZIP64_CENTRAL_DIR_MAGIC) {
                originalFile.readFully(byteArrCentralDirEntry);
                final ByteBuffer byteBufCentralDirEntry = ByteBuffer.wrap(byteArrCentralDirEntry).order(ByteOrder.LITTLE_ENDIAN);
                final CentralDirectoryEntry cdEntry = new CentralDirectoryEntry();

                try {
                    short shortVerMade = byteBufCentralDirEntry.getShort();
                    short shortVerNeeded = byteBufCentralDirEntry.getShort();
                    short shortGenPurpose = byteBufCentralDirEntry.getShort();
                    short shortCompressMethod = byteBufCentralDirEntry.getShort();
                    short shortLastModTime = byteBufCentralDirEntry.getShort();
                    short shortLastModDate = byteBufCentralDirEntry.getShort();
                    int intCrc32 = byteBufCentralDirEntry.getInt();
                    int intCompressedSize = byteBufCentralDirEntry.getInt();
                    int intUncompressedSize = byteBufCentralDirEntry.getInt();
                    short shortFilenameLen = byteBufCentralDirEntry.getShort();
                    short shortExtraFieldLen = byteBufCentralDirEntry.getShort();
                    short shortFileCommentLen = byteBufCentralDirEntry.getShort();
                    short shortDiskNumStart = byteBufCentralDirEntry.getShort();
                    short shortInternalFileAttr = byteBufCentralDirEntry.getShort();
                    int intExternalFileAttr = byteBufCentralDirEntry.getInt();
                    int intLocalHeaderOffset = byteBufCentralDirEntry.getInt();

                    cdEntry.setShortVerMade(shortVerMade);
                    cdEntry.setShortVerNeeded(shortVerNeeded);
                    cdEntry.setShortGenPurpose(shortGenPurpose);
                    cdEntry.setShortCompressMethod(shortCompressMethod);
                    cdEntry.setShortLastModTime(shortLastModTime);
                    cdEntry.setShortLastModDate(shortLastModDate);
                    cdEntry.setIntCrc32(intCrc32);
                    cdEntry.setIntCompressedSize(intCompressedSize);
                    cdEntry.setIntUncompressedSize(intUncompressedSize);
                    cdEntry.setShortFilenameLen(shortFilenameLen);
                    cdEntry.setShortExtraFieldLen(shortExtraFieldLen);
                    cdEntry.setShortFileCommentLen(shortFileCommentLen);
                    cdEntry.setShortDiskNumStart(shortDiskNumStart);
                    cdEntry.setShortInternalFileAttr(shortInternalFileAttr);
                    cdEntry.setIntExternalFileAttr(intExternalFileAttr);
                    cdEntry.setIntLocalHeaderOffset(intLocalHeaderOffset);

                    byte[] byteArrFilename = new byte[(int) shortFilenameLen];

                    originalFile.readFully(byteArrFilename);
                    cdEntry.setByteArrFilename(byteArrFilename);

                    byte[] byteArrExtraField = new byte[(int) shortExtraFieldLen];
                    if (shortExtraFieldLen > 0) {
                        originalFile.readFully(byteArrExtraField);
                        cdEntry.setByteArrExtraField(byteArrExtraField);
                    }
                    byte[] byteArrFileComment = new byte[(int) shortFileCommentLen];
                    if (shortFileCommentLen > 0) {
                        originalFile.readFully(byteArrFileComment);
                        cdEntry.setByteArrFileComment(byteArrFileComment);
                    }

                    listCentralDirEntries.add(cdEntry);

                    longLocalRecOffset = cdEntry.getLongLocalHeaderOffset();
                    long longLocalRecSize = cdEntry.getLongCompressedSize();
                    long longLocalRecUncompressedSize = cdEntry.getLongUncompressedSize();
                    long longCurrentOffset = originalFile.getFilePointer();

                    if (intAppxSignatureIndex > -1 && (intCntEntries == intAppxSignatureIndex + 1)) {
                        longNextOffset = longLocalRecOffset;
                    }

                    if (Arrays.equals(APPX_SIGNATURE_FILENAME.getBytes(StandardCharsets.UTF_8), byteArrFilename)) {
                        LOG.debug("AppxSignature.p7x file found");
                        longAppxSignatureOffset = longLocalRecOffset;
                        intAppxSignatureIndex = intCntEntries;
                    }

                    boolean isContentTypes = false;
                    if (Arrays.equals(CONTENT_TYPES_FILENAME.getBytes(StandardCharsets.UTF_8), byteArrFilename)) {
                        isContentTypes = true;
                        intContentTypesIndex = intCntEntries;
                    }

                    // Process local record
                    //lrUpdated = processLocalRec(rafInput, rafOutput, cdEntry, longLocalRecOffset, longLocalRecSize);

                    if (isContentTypes) {
                        byteArrContentTypesFileData = getInflatedLocalRec(originalFile, longLocalRecOffset, longLocalRecSize);
                    }

                    if (Arrays.equals(APPX_BLOCKMAP_FILENAME.getBytes(StandardCharsets.UTF_8),byteArrFilename)) {
                        byteArrBlockMapFileData = getInflatedLocalRec(originalFile, longLocalRecOffset, longLocalRecSize);
                    }

                    longOriginalEndOffset = lrUpdated.getLongEndOffset();
                                                
                    intCntEntries++;
                } catch (BufferUnderflowException bue) {
                    throw new IllegalRequestException ("Failed to read Central Directory Entry" , bue);
                }
            } else {
                break;
            }
        }

        // Write Local records before AppxSignature.p7x to outfile
        LOG.debug("WRITING RAF");
        final byte[] readBuf = new byte[4096];
        long readCount = 0;
        long readSize = longAppxSignatureOffset;
        long readLen;
        originalFile.seek(0);
        newFile.seek(0);
        while (readCount < readSize) {
            LOG.debug("WRITING RAF");
            readLen = Math.min(readSize - readCount, 4096);
            originalFile.read(readBuf);
            newFile.write(readBuf, 0, (int) readLen);
            readCount += readLen;
        }

        // Write Local records after AppxSignature.p7x to outfile
        long longAppxSignatureEntrySize = lngCDOffset - longAppxSignatureOffset;
        if (longNextOffset > -1) {
            originalFile.seek(longNextOffset);
            readCount = 0;
            readSize = lngCDOffset - longNextOffset;
            while (readCount < readSize) {
                readLen = Math.min(readSize - readCount, 4096);
                originalFile.read(readBuf);
                newFile.write(readBuf,0,(int)readLen);
                readCount += readLen;
            }

            longAppxSignatureEntrySize = Math.min(lngCDOffset, longNextOffset) - longAppxSignatureOffset;
        }

        final long longNewCentralDirOffset = newFile.getFilePointer();
        
        final ByteArrayOutputStream baosReconstructCentralDirectoryRecords = new ByteArrayOutputStream();
        // Reconstruct central directory entries
        for (int intCntDir = 0; intCntDir < intCntEntries; intCntDir++) {

            // Skip AppxSignature.p7x
            if (intCntDir == intAppxSignatureIndex) {
                continue;
            }

            CentralDirectoryEntry cdeEntry = listCentralDirEntries.get(intCntDir);

            int intUncompressedSize;
            int intCompressedSize;
            int intCrc32;

            final short shortGenPurposeFlag = cdeEntry.getShortGenPurpose();

            intUncompressedSize = (int) cdeEntry.getLongUncompressedSize();
            intCompressedSize = (int) cdeEntry.getLongCompressedSize();
            intCrc32 = cdeEntry.getIntCrc32();
            

            baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(ZIP64_CENTRAL_DIR_MAGIC));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortVerMade()));
            
            // Set version needed based on the original value of the general purpose flag
            if (shortGenPurposeFlag == ZIP64_GENERAL_PURPOSE_8) {
                baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(ZIP64_VERSION_NEEDED_45));
                baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(ZIP64_GENERAL_PURPOSE_8));
            }
            else {
                baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(ZIP64_VERSION_NEEDED_20));
                baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(ZIP64_GENERAL_PURPOSE_0));
            }
            
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortCompressMethod()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortLastModTime()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortLastModDate()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(intCrc32));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(intCompressedSize));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(intUncompressedSize));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortFilenameLen()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian((short)0)); //Remove extra field
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortFileCommentLen()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortDiskNumStart()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.shortToLittleEndian(cdeEntry.getShortInternalFileAttr()));
            baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(cdeEntry.getIntExternalFileAttr()));
            if (intCntDir < intAppxSignatureIndex) {
                baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(cdeEntry.getIntLocalHeaderOffset()));
            }
            else {
                baosReconstructCentralDirectoryRecords.write(ZipUtil.intToLittleEndian(cdeEntry.getIntLocalHeaderOffset() - (int) longAppxSignatureEntrySize));
            }
            baosReconstructCentralDirectoryRecords.write(cdeEntry.getByteArrFilename());
            baosReconstructCentralDirectoryRecords.write(cdeEntry.getByteArrFileComment());
        }

        final byte[] byteArrReconstructedCentralDirRecords = baosReconstructCentralDirectoryRecords.toByteArray();

        newFile.write(byteArrReconstructedCentralDirRecords);

        final byte[] byteArrFinalEocd = eocdValues.getEocdVerify(byteArrReconstructedCentralDirRecords.length, longNewCentralDirOffset, 
            longNewCentralDirOffset + byteArrReconstructedCentralDirRecords.length);

        newFile.write(byteArrFinalEocd);

        // Calculate message digests
        final ByteArrayOutputStream digestBytes = new ByteArrayOutputStream();
        digestBytes.write(APPX_DIGEST_SIGNATURE);
        digestBytes.write(APPX_AXPC_SIGNATURE);

        try {
            // Digest Local Records
            newFile.seek(0);
            readCount = 0;

            final MessageDigest mdZipRec = MessageDigest.getInstance(digestAlgorithm);
                
            while (readCount < longNewCentralDirOffset) {
                readLen = Math.min(longNewCentralDirOffset - readCount, 4096);
                newFile.read(readBuf);
                mdZipRec.update(readBuf, 0, (int) readLen);
                readCount += readLen;
            }

            final byte[] byteArrZipRecDigest = mdZipRec.digest();

            // Digest Central Directory to EOF
            newFile.seek(longNewCentralDirOffset);
            int intCdRead = 0;
            final byte[] byteCdBuf = new byte[4096];
            final MessageDigest mdCdDigest = MessageDigest.getInstance(digestAlgorithm);

            while (-1 != (intCdRead = newFile.read(byteCdBuf))) {
                mdCdDigest.update(byteCdBuf,0,intCdRead);
            }

            byte[] mdCdDigestNew = mdCdDigest.digest();

            digestBytes.write(byteArrZipRecDigest);
            digestBytes.write(APPX_AXCD_SIGNATURE);
            digestBytes.write(mdCdDigestNew);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalRequestException("Digest Alogorithm not supported", ex);
        }

        byte[] appxBlockMapDigest = new byte[0];
        byte[] contentTypesDigest = new byte[0];

        int direntrysize = 0;
        long filerecordsize = 0;

        // Digest inflated AppxBlockMap.xml and [Content_Types].xml
        if (byteArrBlockMapFileData.length > 0) {
            try {
                final MessageDigest mdpart = MessageDigest.getInstance(digestAlgorithm);          
                InputStream inBlockMap = new ByteArrayInputStream(byteArrBlockMapFileData);
                appxBlockMapDigest = digest(inBlockMap, mdpart);
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalRequestException("Log digest algorithm not supported", ex);
            }
        } else {
            throw new IllegalRequestException("Invalid Appx file. Missing AppxBlockMap.xml data.");
        }

        if (byteArrContentTypesFileData.length > 0) {
            try {
                final MessageDigest mdpart = MessageDigest.getInstance(digestAlgorithm);

                InputStream inContentTypes = new ByteArrayInputStream(byteArrContentTypesFileData);
                contentTypesDigest = digest(inContentTypes, mdpart);
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalRequestException("Log digest algorithm not supported", ex);
            }    
        } else {
            throw new IllegalRequestException("Invalid Appx file. Missing [Content_Types].xml.");
        }
        
        digestBytes.write(APPX_AXCT_SIGNATURE);
        digestBytes.write(contentTypesDigest);
        digestBytes.write(APPX_AXBM_SIGNATURE);
        digestBytes.write(appxBlockMapDigest);
        digestBytes.write(APPX_AXCI_SIGNATURE);

        final byte[] finalDigest = digestBytes.toByteArray();

        // Pad with 0x00 if digest is < 184 bytes;
        final ByteArrayOutputStream baosPad = new ByteArrayOutputStream();
        baosPad.write(finalDigest);
        if (finalDigest.length < 184) {
            for (int cnt = 0; cnt < 184 - finalDigest.length; cnt++) {
                baosPad.write(0x00);
            }
        }

        final byte[] paddedDigest = baosPad.toByteArray();
        return paddedDigest;
    }

    public static byte[] digest(InputStream input, MessageDigest md) throws IOException {
        final byte[] buffer = new byte[4096];
        int n = 0;
        while (-1 != (n = input.read(buffer))) {
            md.update(buffer, 0, n);
        }
        return md.digest();
    }

    private static class CentralDirectoryEntry {

        public CentralDirectoryEntry() {
            this.byteArrFilename = new byte[0];
            this.byteArrExtraField = new byte[0];
            this.byteArrFileComment = new byte[0];
        }

        private short shortVerMade;
        private short shortVerNeeded;
        private short shortGenPurpose;
        private short shortCompressMethod;
        private short shortLastModTime;
        private short shortLastModDate;
        private int intCrc32;
        private int intCompressedSize;
        private int intUncompressedSize;
        private short shortFilenameLen;
        private short shortExtraFieldLen;
        private short shortFileCommentLen;
        private short shortDiskNumStart;
        private short shortInternalFileAttr;
        private int intExternalFileAttr;
        private int intLocalHeaderOffset;
        private short shortExtraFieldTagEntry;
        private short shortExtraFieldSizeEntry;

        private byte[] byteArrFilename;
        private byte[] byteArrExtraField;
        private byte[] byteArrFileComment;

        // Updated Local Header Offset
        private long longNewLocalHeaderOffset;

        public short getShortVerMade() {
            return this.shortVerMade;
        }

        public short getShortVerNeeded() {
            return this.shortVerNeeded;
        }

        public short getShortGenPurpose() {
            return this.shortGenPurpose;
        }

        public short getShortCompressMethod() {
            return this.shortCompressMethod;
        }

        public short getShortLastModTime() {
            return this.shortLastModTime;
        }

        public short getShortLastModDate() {
            return this.shortLastModDate;
        }

        public int getIntCrc32() {
            return this.intCrc32;
        }

        public int getIntCompressedSize() {
            return this.intCompressedSize;
        }

        public int getIntUncompressedSize() {
            return this.intUncompressedSize;
        }

        public short getShortFilenameLen() {
            return this.shortFilenameLen;
        }

        public short getShortExtraFieldLen() {
            return this.shortExtraFieldLen;
        }

        public short getShortFileCommentLen() {
            return this.shortFileCommentLen;
        }

        public short getShortDiskNumStart() {
            return this.shortDiskNumStart;
        }

        public short getShortInternalFileAttr() {
            return this.shortInternalFileAttr;
        }

        public int getIntExternalFileAttr() {
            return this.intExternalFileAttr;
        }

        public int getIntLocalHeaderOffset() {
            return this.intLocalHeaderOffset;
        }

        public byte[] getByteArrFilename() {
            return this.byteArrFilename;
        }

        public byte[] getByteArrExtraField() {
            return this.byteArrExtraField;
        }

        public byte[] getByteArrFileComment() {
            return this.byteArrFileComment;
        }

        public short getShortExtraFieldTagEntry() {
            return this.shortExtraFieldTagEntry;
        }

        public short getShortExtraFieldSizeEntry() {
            return this.shortExtraFieldSizeEntry;
        }

        public long getLongNewLocalHeaderOffset() {
            return this.longNewLocalHeaderOffset;
        }

        public void setShortVerMade(short verMade) {
            this.shortVerMade = verMade ;
        }

        public void setShortVerNeeded(short verNeeded) {
            this.shortVerNeeded = verNeeded;
        }

        public void setShortGenPurpose(short genPurpose) {
            this.shortGenPurpose = genPurpose;
        }

        public void setShortCompressMethod(short compressMethod) {
            this.shortCompressMethod = compressMethod;
        }

        public void setShortLastModTime(short lastModTime) {
            this.shortLastModTime = lastModTime;
        }

        public void setShortLastModDate(short lastModDate) {
            this.shortLastModDate = lastModDate;
        }

        public void setIntCrc32(int crc32) {
            this.intCrc32 = crc32;
        }

        public void setIntCompressedSize(int compressedSize) {
            this.intCompressedSize = compressedSize;
        }

        public void setIntUncompressedSize(int uncompressedSize) {
            this.intUncompressedSize = uncompressedSize;
        }

        public void setShortFilenameLen(short filenameLen) {
            this.shortFilenameLen = filenameLen;
        }

        public void setShortExtraFieldLen(short extraFieldLen) {
            this.shortExtraFieldLen = extraFieldLen;
        }

        public void setShortFileCommentLen(short fileCommentLen) {
            this.shortFileCommentLen = fileCommentLen;
        }

        public void setShortDiskNumStart(short diskNumStart) {
            this.shortDiskNumStart = diskNumStart;
        }

        public void setShortInternalFileAttr(short internalFileAttr) {
            this.shortInternalFileAttr = internalFileAttr;
        }

        public void setIntExternalFileAttr(int externalFileAttr) {
            this.intExternalFileAttr = externalFileAttr;
        }

        public void setIntLocalHeaderOffset(int localHeaderOffset) {
            this.intLocalHeaderOffset = localHeaderOffset;
        }

        public void setByteArrFilename(byte[] filename) {
            this.byteArrFilename = filename;
        }

        public void setByteArrExtraField(byte[] extraField) {
            this.byteArrExtraField = extraField;
            ByteBuffer buf = ByteBuffer.wrap(extraField).order(ByteOrder.LITTLE_ENDIAN);
            this.shortExtraFieldTagEntry = buf.getShort();
            this.shortExtraFieldSizeEntry = buf.getShort();
        }

        public void setByteArrFileComment(byte[] fileComment) {
            this.byteArrFileComment = fileComment;
        }

        public long getLongLocalHeaderOffset() throws IllegalRequestException {
            // If local Header Offset is 0xFFFFFF, it is defined in the extra field
            if (this.intLocalHeaderOffset == 0xFFFFFFFF) {
                if (this.shortExtraFieldLen > 0 && this.byteArrExtraField.length >= 28) { 
                    try {
                        ByteBuffer  buf = ByteBuffer.wrap(this.byteArrExtraField).order(ByteOrder.LITTLE_ENDIAN);
                        final short shortTag = buf.getShort();
                        final short shortSize = buf.getShort();
                        final long longUncompressedSize = buf.getLong();
                        final long longCompressedSize = buf.getLong();
                        final long longLocalHeaderOffset = buf.getLong();
                        return longLocalHeaderOffset;
                    } catch (BufferUnderflowException bue) {
                        throw new IllegalRequestException("Error reading central directory extra field", bue);
                    }
                } else {
                    throw new IllegalRequestException("Invalid length for central directory extra field");
                }
            } else {
                return (long) this.intLocalHeaderOffset;
            }
        }

        public long getLongCompressedSize() throws IllegalRequestException {
            // If local Header Offset is 0xFFFFFF, it is defined in the extra field
            if (this.intCompressedSize == 0xFFFFFFFF) {
                if (this.shortExtraFieldLen > 0 && this.byteArrExtraField.length >= 28) {
                    try {
                        ByteBuffer  buf = ByteBuffer.wrap(this.byteArrExtraField).order(ByteOrder.LITTLE_ENDIAN);
                        final short shortTag = buf.getShort();
                        final short shortSize = buf.getShort();
                        final long longUncompressedSize = buf.getLong();
                        final long longCompressedSize = buf.getLong();
                        final long longLocalHeaderOffset = buf.getLong();
                        return longCompressedSize;
                    } catch (BufferUnderflowException bue) {
                        throw new IllegalRequestException("Error reading central directory extra field", bue);
                    }
                } else {
                    throw new IllegalRequestException("Invalid length for central directory extra field");
                }
            } else {
                return (long) this.intCompressedSize;
            }
        }

        public long getLongUncompressedSize() throws IllegalRequestException {
            // If local Header Offset is 0xFFFFFF, it is defined in the extra field
            if (this.intUncompressedSize == 0xFFFFFFFF) {
                if (this.shortExtraFieldLen > 0 && this.byteArrExtraField.length >= 28) {
                    try {
                        ByteBuffer  buf = ByteBuffer.wrap(this.byteArrExtraField).order(ByteOrder.LITTLE_ENDIAN);
                        final short shortTag = buf.getShort();
                        final short shortSize = buf.getShort();
                        final long longUncompressedSize = buf.getLong();
                        final long longCompressedSize = buf.getLong();
                        final long longLocalHeaderOffset = buf.getLong();
                        return longUncompressedSize;
                    } catch (BufferUnderflowException bue) {
                        throw new IllegalRequestException("Error reading central directory extra field", bue);
                    }
                } else {
                    throw new IllegalRequestException("Invalid length for central directory extra field");
                }
            } else {
                return (long)this.intUncompressedSize;
            }
        }

        public void setLongNewLocalHeaderOffset(long newLocalHeaderOffset) {
          this.longNewLocalHeaderOffset = newLocalHeaderOffset;
        }
    }

    private static class LocalRecord {

        private short shortVerNeeded;
        private short shortGenPurpose;
        private short shortCompressMethod;
        private short shortLastModTime;
        private short shortLastModDate;
        private int intCrc32;
        private int intCompressedSize;
        private int intUncompressedSize;
        private short shortFilenameLen;
        private short shortExtraFieldLen;
        private long longEndOffset;  //Original offset for end of [Content_Types].xml local record
        private long longUpdatedCrc32;
        private long longUpdatedUncompressedSize;
        private long longUpdatedCompressedSize; 
        private int intDdCrc32; // CRC32 from data descriptor
        private long longDdUncompressedSize; // Uncompressed Size from data descriptor
        private long longDdCompressedSize; // Compressed Size from data descriptor

        private byte[] byteArrFilename;
        private byte[] byteArrExtraField;
        private byte[] byteArrExtendedInfo;
        private byte[] byteArrDataDescriptorShort;
        private byte[] byteArrDataDescriptorLong;
        private byte[] byteArrInflatedRecord;
        private byte[] byteArrModifiedRecord;
        private boolean hasDataDescriptor;
        private boolean isDataDescriptorLong; //has zip64 Data Descriptor with long values

        public LocalRecord() {
            hasDataDescriptor = false;
            isDataDescriptorLong = true;
            byteArrModifiedRecord = new byte[0];
        }

        public short getShortVerNeeded() {
            return this.shortVerNeeded;
        }

        public short getShortGenPurpose() {
            return this.shortGenPurpose;
        }

        public short getShortCompressMethod() {
            return this.shortCompressMethod;
        }

        public short getShortLastModTime() {
            return this.shortLastModTime;
        }

        public short getShortLastModDate() {
            return this.shortLastModDate;
        }

        public int getIntCrc32() {
            return this.intCrc32;
        }

        public int getIntCompressedSize() {
            return this.intCompressedSize;
        }

        public int getIntUncompressedSize() {
            return this.intUncompressedSize;
        }

        public short getShortFilenameLen() {
            return this.shortFilenameLen;
        }

        public short getShortExtraFieldLen() {
            return this.shortExtraFieldLen;
        }

        public byte[] getByteArrFilename() {
            return this.byteArrFilename;
        }

        public byte[] getByteArrExtraField() {
            return this.byteArrExtraField;
        }

        public byte[] getByteArrExtendedInfo() {
            return this.byteArrExtendedInfo;
        }

        public byte[] getByteArrDataDescriptorShort() {
            return this.byteArrDataDescriptorShort;
        }

        public byte[] getByteArrDataDescriptorLong() {
            return this.byteArrDataDescriptorLong;
        }

        public boolean getHasDataDescriptor() {
            return this.hasDataDescriptor;
        }

        public boolean getIsDataDescriptorLong() {
            return this.isDataDescriptorLong;
        }

        public long getLongEndOffset() {
            return this.longEndOffset;
        }

        public byte[] getByteArrModifiedRecord() {
            return this.byteArrModifiedRecord;
        }

        public byte[] getByteArrInflatedRecord() {
            return this.byteArrInflatedRecord;
        }

        public long getLongUpdatedCrc32() {
            return this.longUpdatedCrc32;
        }

        public long getLongUpdatedCompressedSize() {
            return this.longUpdatedCompressedSize;
        }
        public long getLongUpdatedUncompressedSize() {
            return this.longUpdatedUncompressedSize;
        }

        public int getIntDdCrc32() {
            return this.intDdCrc32;
        }

        public long getLongDdCompressedSize() {
            return this.longDdCompressedSize;
        }
        public long getLongDdUncompressedSize() {
            return this.longDdUncompressedSize;
        }

        public void setShortVerNeeded(short verNeeded) {
            this.shortVerNeeded = verNeeded;
        }

        public void setShortGenPurpose(short genPurpose) {
            this.shortGenPurpose = genPurpose;
        }

        public void setShortCompressMethod(short compressMethod) {
            this.shortCompressMethod = compressMethod;
        }

        public void setShortLastModTime(short lastModTime) {
            this.shortLastModTime = lastModTime;
        }

        public void setShortLastModDate(short lastModDate) {
            this.shortLastModDate = lastModDate;
        }

        public void setIntCrc32(int crc32) {
            this.intCrc32 = crc32;
        }

        public void setIntCompressedSize(int compressedSize) {
            this.intCompressedSize = compressedSize;
        }

        public void setIntUncompressedSize(int uncompressedSize) {
            this.intUncompressedSize = uncompressedSize;
        }

        public void setShortFilenameLen(short filenameLen) {
            this.shortFilenameLen = filenameLen;
        }

        public void setShortExtraFieldLen(short extraFieldLen) {
            this.shortExtraFieldLen = extraFieldLen;
        }

        public void setByteArrFilename(byte[] filename) {
            this.byteArrFilename = filename;
        }

        public void setByteArrExtraField(byte[] extraField) {
            this.byteArrExtraField = extraField;
        }

        public void setByteArrExtendedInfo(byte[] extendedInfo) {
            this.byteArrExtendedInfo = extendedInfo;
        }

        public void setByteArrDataDescriptorLong(byte[] dataDescriptorLong) {
            this.byteArrDataDescriptorLong = dataDescriptorLong;
        }

        public void setByteArrDataDescriptorShort(byte[] dataDescriptorShort) {
            this.byteArrDataDescriptorShort = dataDescriptorShort;
        }

        public void setHasDataDescriptor(boolean hasDataDescriptorFlag) {
            this.hasDataDescriptor = hasDataDescriptorFlag;
        }
        

        public void setIsDataDescriptorLong(boolean dataDescriptorLongFlag){
            this.isDataDescriptorLong = dataDescriptorLongFlag;
        }

        public void setLongEndOffset(long endOffset) {
            this.longEndOffset = endOffset;
        }

        public void setByteArrModifiedRecord(byte[] modifiedRecord) {
            this.byteArrModifiedRecord = modifiedRecord;
        }

        public void setByteArrInflatedRecord(byte[] inflatedRecord) {
            this.byteArrInflatedRecord = inflatedRecord;
        }

        public void setLongUpdatedCrc32(long updatedCrc32) {
            this.longUpdatedCrc32 = updatedCrc32;
        }

        public void setLongUpdatedCompressedSize(long compressedSize) {
            this.longUpdatedCompressedSize = compressedSize;
        }

        public void setLongUpdatedUncompressedSize(long uncompressedSize) {
            this.longUpdatedUncompressedSize = uncompressedSize;
        }

        public void setIntDdCrc32(int ddCrc32) {
            this.intDdCrc32 = ddCrc32;
        }

        public void setLongDdCompressedSize(long ddCompressedSize) {
            this.longDdCompressedSize = ddCompressedSize;
        }

        public void setLongDdUncompressedSize(long ddUncompressedSize) {
            this.longDdUncompressedSize = ddUncompressedSize;
        }


    }
    
    private static byte[] getInflatedLocalRec(RandomAccessFile inputRaf, long localRecOffset, long localRecSize) throws IOException, IllegalRequestException {
        // Get current pointer position
        final long ptr = inputRaf.getFilePointer();

        // Seek local record offset
        inputRaf.seek(localRecOffset);
        
        final byte[] byteArrContent = new byte[(int) localRecSize]; // [Content_Types].xml, AppxBlockMap.xml file data
        final byte[] byteLocalRecHeader = new byte[ZIP64_LOCAL_HEADER_SIZE];

        final byte[] byteArrInflatedRecord;

        if (Integer.reverseBytes(inputRaf.readInt()) == ZIP64_LOCAL_HEADER_MAGIC) {
            inputRaf.readFully(byteLocalRecHeader);
            final ByteBuffer byteBufLrHeader = ByteBuffer.wrap(byteLocalRecHeader).order(ByteOrder.LITTLE_ENDIAN);
                            
            short shortVerNeeded = byteBufLrHeader.getShort();
            short shortGenPurpose = byteBufLrHeader.getShort();
            short shortCompressMethod = byteBufLrHeader.getShort();
            short shortLastModTime = byteBufLrHeader.getShort();
            short shortLastModDate = byteBufLrHeader.getShort();
            int intCrc32 = byteBufLrHeader.getInt();
            int intCompressedSize = byteBufLrHeader.getInt();
            int intUncompressedSize = byteBufLrHeader.getInt();
            short shortFilenameLen = byteBufLrHeader.getShort();
            short shortExtraFieldLen = byteBufLrHeader.getShort();
                            
            final byte[] byteArrFilename = new byte[(int) shortFilenameLen];
            inputRaf.readFully(byteArrFilename);
            
            final byte[] byteArrExtraField = new byte[(int) shortExtraFieldLen];
            if (shortExtraFieldLen > 0) {
                inputRaf.readFully(byteArrExtraField);
            }

            // Input file offset before file data
            long longBeforeData = inputRaf.getFilePointer();
            boolean isContentTypes = false;
            boolean isAppxBlockMap = false;

            inputRaf.readFully(byteArrContent);

            // Save inflated AppxBlockMap.xml or [Content_Types].xml for digestion            
            if (shortCompressMethod == 8) {
                try {
                    Inflater decompresser = new Inflater(true);
                    decompresser.setInput(byteArrContent);

                    final ByteArrayOutputStream baosBlockMap = new ByteArrayOutputStream();
                    final byte[] buf = new byte[1024];
                    while (!decompresser.finished()) {
                        int count = decompresser.inflate(buf);
                        baosBlockMap.write(buf,0,count);
                    }
                    byteArrInflatedRecord = baosBlockMap.toByteArray();

                } catch (DataFormatException ex) {
                    throw new IllegalRequestException("Error inflating AppxBlockMap.xml", ex);
                }
            } else {
                byteArrInflatedRecord = byteArrContent;
            }
        } else {
            throw new IllegalRequestException("Local record signature not found. Invalid file.");
        }

        inputRaf.seek(ptr);

        return byteArrInflatedRecord;
    }

    private static LocalRecord processLocalRec(RandomAccessFile inputRaf, RandomAccessFile outRaf, CentralDirectoryEntry cdEntry, long localRecOffset, long localRecSize) throws IOException, IllegalRequestException {
        // Get current pointer position
        final long ptr = inputRaf.getFilePointer();
        
        // Seek local record offset
        inputRaf.seek(localRecOffset);
        
        byte[] byteArrContent; // [Content_Types].xml file data

        final byte[] byteLocalRecHeader = new byte[ZIP64_LOCAL_HEADER_SIZE];

        final LocalRecord lrCurrentRec = new LocalRecord();
        if (Integer.reverseBytes(inputRaf.readInt()) == ZIP64_LOCAL_HEADER_MAGIC) {
            inputRaf.readFully(byteLocalRecHeader);
            final ByteBuffer byteBufLrHeader = ByteBuffer.wrap(byteLocalRecHeader).order(ByteOrder.LITTLE_ENDIAN);
                            
            final short shortVerNeeded = byteBufLrHeader.getShort();
            final short shortGenPurpose = byteBufLrHeader.getShort();
            final short shortCompressMethod = byteBufLrHeader.getShort();
            final short shortLastModTime = byteBufLrHeader.getShort();
            final short shortLastModDate = byteBufLrHeader.getShort();
            final int intCrc32 = byteBufLrHeader.getInt();
            final int intCompressedSize = byteBufLrHeader.getInt();
            final int intUncompressedSize = byteBufLrHeader.getInt();
            final short shortFilenameLen = byteBufLrHeader.getShort();
            final short shortExtraFieldLen = byteBufLrHeader.getShort();
                            
            final byte[] byteArrFilename = new byte[(int) shortFilenameLen];

            inputRaf.readFully(byteArrFilename);
            
            final byte[] byteArrExtraField = new byte[(int) shortExtraFieldLen];
            if (shortExtraFieldLen > 0) {
                inputRaf.readFully(byteArrExtraField);
            }

            lrCurrentRec.setShortVerNeeded(shortVerNeeded);
            lrCurrentRec.setShortGenPurpose(shortGenPurpose);
            lrCurrentRec.setShortCompressMethod(shortCompressMethod);
            lrCurrentRec.setShortLastModTime(shortLastModTime);
            lrCurrentRec.setShortLastModDate(shortLastModDate);
            lrCurrentRec.setIntCrc32(intCrc32);
            lrCurrentRec.setIntCompressedSize(intCompressedSize);
            lrCurrentRec.setIntUncompressedSize(intUncompressedSize);
            lrCurrentRec.setShortFilenameLen(shortFilenameLen);
            lrCurrentRec.setShortExtraFieldLen(shortExtraFieldLen);
            lrCurrentRec.setByteArrFilename(byteArrFilename);
            lrCurrentRec.setByteArrExtraField(byteArrExtraField);  
        } else {
            throw new IllegalRequestException("Local record signature not found. Invalid file.");
        }

        // Input file offset before file data
        final long longBeforeData = inputRaf.getFilePointer();
        boolean isContentTypes = false;
        boolean isAppxBlockMap = false;

        // If current record is [Content_Types].xml, read compressed file data to byte array
        // Otherwise skip to offset following compressed file data to read Data Descriptor
        if (Arrays.equals(CONTENT_TYPES_FILENAME.getBytes(StandardCharsets.UTF_8),lrCurrentRec.getByteArrFilename())) {
            isContentTypes = true;
        } else if (Arrays.equals(APPX_BLOCKMAP_FILENAME.getBytes(StandardCharsets.UTF_8),lrCurrentRec.getByteArrFilename())) {
            isAppxBlockMap = true;
        }

        if (isContentTypes || isAppxBlockMap) {
            byteArrContent = new byte[(int)localRecSize];
            inputRaf.readFully(byteArrContent);

            // Save inflated AppxBlockMap.xml for digestion
            if (isAppxBlockMap) {
                if (lrCurrentRec.getShortCompressMethod() == 8) {
                    try {
                        final Inflater decompresser = new Inflater(true);
                        decompresser.setInput(byteArrContent);

                        final ByteArrayOutputStream baosBlockMap = new ByteArrayOutputStream();
                        final byte[] buf = new byte[1024];
                        while (!decompresser.finished()) {
                            int count = decompresser.inflate(buf);
                            baosBlockMap.write(buf,0,count);
                        }
                        baosBlockMap.close();
                        lrCurrentRec.setByteArrInflatedRecord(baosBlockMap.toByteArray());
                    } catch (java.util.zip.DataFormatException ex) {
                        throw new IllegalRequestException("Error inflating AppxBlockMap.xml", ex);
                    }
                } else {
                    lrCurrentRec.setByteArrInflatedRecord(byteArrContent);
                }
            }
        } else {
            byteArrContent = new byte[0]; // Set as empty byte array for other entries to prevent overflow
            inputRaf.seek(longBeforeData + cdEntry.getLongCompressedSize());
        }

        // Read Data Descriptor if it exists
        // Note: for zip64, data descriptor should be 20 bytes (LONG) not including magic bytes
        final byte[] byteArrDataDescriptorShort = new byte[ZIP64_DATA_DESCRIPTOR_SHORT_LEN];
        final byte[] byteArrDataDescriptorLong = new byte[ZIP64_DATA_DESCRIPTOR_LONG_LEN];
        
        boolean hasDataDescriptor = false;
        boolean isDataDescriptorLong = false;
        
        if (Integer.reverseBytes(inputRaf.readInt()) == ZIP64_DATA_DESCRIPTOR_MAGIC) {
            final long longEndDataPtr = inputRaf.getFilePointer();
            inputRaf.readFully(byteArrDataDescriptorLong);
            int intNextHeader = Integer.reverseBytes(inputRaf.readInt());
            if (intNextHeader == ZIP64_CENTRAL_DIR_MAGIC || intNextHeader == ZIP64_LOCAL_HEADER_MAGIC) {
                lrCurrentRec.setByteArrDataDescriptorLong(byteArrDataDescriptorLong);
                isDataDescriptorLong = true;

                try {
                    final ByteBuffer buf = ByteBuffer.wrap(byteArrDataDescriptorLong).order(ByteOrder.LITTLE_ENDIAN);
                    
                    final int intDdCrc32 = buf.getInt();
                    final long longDdCompressedSize = buf.getLong();
                    final long longDdUncompressedSize = buf.getLong();
                    lrCurrentRec.setIntDdCrc32(intDdCrc32);
                    lrCurrentRec.setLongDdCompressedSize(longDdCompressedSize);
                    lrCurrentRec.setLongDdUncompressedSize(longDdUncompressedSize);
                } catch (BufferUnderflowException bue) {
                    throw new IllegalRequestException("Error parsing data descriptor", bue);
                }
            } else {
                // Note: Just in case compressed/uncompressed sizes are ints.
                inputRaf.seek(longEndDataPtr);
                inputRaf.readFully(byteArrDataDescriptorShort);
                intNextHeader = Integer.reverseBytes(inputRaf.readInt());
                if (intNextHeader == ZIP64_CENTRAL_DIR_MAGIC || intNextHeader == ZIP64_LOCAL_HEADER_MAGIC) {
                    lrCurrentRec.setByteArrDataDescriptorShort(byteArrDataDescriptorShort);
                    isDataDescriptorLong = false;

                    try {
                        final ByteBuffer buf = ByteBuffer.wrap(byteArrDataDescriptorShort).order(ByteOrder.LITTLE_ENDIAN);
                        
                        final int intDdCrc32 = buf.getInt();
                        final int intDdCompressedSize = buf.getInt();
                        final int intDdUncompressedSize = buf.getInt();
                        lrCurrentRec.setIntDdCrc32(intDdCrc32);
                        lrCurrentRec.setLongDdCompressedSize((long)intDdCompressedSize);
                        lrCurrentRec.setLongDdUncompressedSize((long)intDdUncompressedSize);
                    } catch (BufferUnderflowException bue) {
                        throw new IllegalRequestException("Error parsing data descriptor", bue);
                    }
                } else {
                    throw new IllegalRequestException("Invalid Data Descriptor");
                }
            }
            hasDataDescriptor = true;
            inputRaf.seek(inputRaf.getFilePointer() - 4); // Undo read of following magic bytes
        }

        lrCurrentRec.setHasDataDescriptor(hasDataDescriptor);
        lrCurrentRec.setIsDataDescriptorLong(isDataDescriptorLong);

        // Note the original end offset for local record before changing structure
        lrCurrentRec.setLongEndOffset(inputRaf.getFilePointer());
        
        // Write Record to outFile
        // Note the new local header offset
        final long longNewLocalHeaderOffset = outRaf.getFilePointer();
        cdEntry.setLongNewLocalHeaderOffset(longNewLocalHeaderOffset);

        // Write Local Record contents for files other than [Content_Types].xml
        if (!isContentTypes) {
            final ByteArrayOutputStream baosReconstructLocalRecord = new ByteArrayOutputStream();
            baosReconstructLocalRecord.write(ZipUtil.intToLittleEndian(ZIP64_LOCAL_HEADER_MAGIC));
            final short shortNotCtGenPurpose = lrCurrentRec.getShortGenPurpose();

            // For all files other than [Content_Types].xml set version needed based on the original value of the general purpose flag
            if (shortNotCtGenPurpose == ZIP64_GENERAL_PURPOSE_8) {
                baosReconstructLocalRecord.write(ZipUtil.shortToLittleEndian(ZIP64_VERSION_NEEDED_45));
                baosReconstructLocalRecord.write(ZipUtil.shortToLittleEndian(ZIP64_GENERAL_PURPOSE_8));
            } else {
                baosReconstructLocalRecord.write(ZipUtil.shortToLittleEndian(ZIP64_VERSION_NEEDED_20));
                baosReconstructLocalRecord.write(ZipUtil.shortToLittleEndian(ZIP64_GENERAL_PURPOSE_0));                
            }

            baosReconstructLocalRecord.write(ZipUtil.shortToLittleEndian(lrCurrentRec.getShortCompressMethod()));
            baosReconstructLocalRecord.write(ZipUtil.shortToLittleEndian(lrCurrentRec.getShortLastModTime()));
            baosReconstructLocalRecord.write(ZipUtil.shortToLittleEndian(lrCurrentRec.getShortLastModDate()));

            final int intCrc32 = lrCurrentRec.getIntCrc32();
            final int intCompressedSize = lrCurrentRec.getIntCompressedSize();
            final int intUncompressedSize = lrCurrentRec.getIntUncompressedSize();

            // If record has Data Descriptor, set CRC32, compressed size, and uncompressed size to 0 in regular header
            if ((intCrc32 == 0 && intCompressedSize == 0 && intUncompressedSize == 0) && lrCurrentRec.getHasDataDescriptor()) {
                baosReconstructLocalRecord.write(ZipUtil.intToLittleEndian(0));
                baosReconstructLocalRecord.write(ZipUtil.intToLittleEndian(0));
                baosReconstructLocalRecord.write(ZipUtil.intToLittleEndian(0));
            } else {
                baosReconstructLocalRecord.write(ZipUtil.intToLittleEndian(lrCurrentRec.getIntCrc32()));
                baosReconstructLocalRecord.write(ZipUtil.intToLittleEndian(lrCurrentRec.getIntCompressedSize()));
                baosReconstructLocalRecord.write(ZipUtil.intToLittleEndian(lrCurrentRec.getIntUncompressedSize()));
            }
 
            baosReconstructLocalRecord.write(ZipUtil.shortToLittleEndian(lrCurrentRec.getShortFilenameLen()));
            baosReconstructLocalRecord.write(ZipUtil.shortToLittleEndian(lrCurrentRec.getShortExtraFieldLen()));
            baosReconstructLocalRecord.write(lrCurrentRec.getByteArrFilename());
            baosReconstructLocalRecord.write(lrCurrentRec.getByteArrExtraField());

            // Write reconstructed local header to the output file (workspace)
            outRaf.write(baosReconstructLocalRecord.toByteArray());
            
            long readCount = 0;
            long readLen;
            final byte[] readBuf = new byte[4096];

            // Reposition pointer to offset for compressed file data
            inputRaf.seek(longBeforeData);

            // Write compressed file data to workspace
            final long longReadSize = cdEntry.getLongCompressedSize();
            while (readCount < longReadSize) {
                readLen = Math.min(longReadSize - readCount, 4096);
                inputRaf.read(readBuf);
                outRaf.write(readBuf,0,(int)readLen);
                readCount += readLen;
            }

            // If the record had a Data Descriptor, write it to the output file workspace
            if (lrCurrentRec.getHasDataDescriptor()) {
                //Keep Data Descriptor for entries other than [Content_Types].xml
                outRaf.write(ZipUtil.intToLittleEndian(ZIP64_DATA_DESCRIPTOR_MAGIC));
                outRaf.write(lrCurrentRec.getByteArrDataDescriptorLong());
            }
        }

        inputRaf.seek(ptr);

        byte[] byteArrUpdatedXml;

        if (isContentTypes) {
            try {
                // Decompress the bytes if compression method is DEFLATE
                if (lrCurrentRec.getShortCompressMethod() == 8) {
                    Inflater decompresser = new Inflater(true);
                    decompresser.setInput(byteArrContent);

                    ByteArrayOutputStream baosCt = new ByteArrayOutputStream();
                    byte[] buf = new byte[1024];
                    while (!decompresser.finished()) {
                        int count = decompresser.inflate(buf);
                        baosCt.write(buf, 0, count);
                    }
                    baosCt.close();

                    // Convert the bytes to a String (UTF-8)
                    String outputString = new String(baosCt.toByteArray(), StandardCharsets.UTF_8);
                    byteArrUpdatedXml = parseContentTypesXML(baosCt.toByteArray());

                    if (byteArrUpdatedXml.length == 0) {
                        //XML was not modified
                        lrCurrentRec.setByteArrModifiedRecord(byteArrUpdatedXml); //size 0
                        lrCurrentRec.setByteArrInflatedRecord(baosCt.toByteArray());
                    }
                    else {
                        // Save inflated [Content_Types].xml file bytes
                        lrCurrentRec.setByteArrInflatedRecord(byteArrUpdatedXml);
                        final long longUpdatedXmlSize = (long)byteArrUpdatedXml.length; // uncompressed size
                        lrCurrentRec.setLongUpdatedUncompressedSize(longUpdatedXmlSize);

                        final ByteArrayOutputStream baosDeflate = new ByteArrayOutputStream();

                        // Deflate modified [Content_Types].xml
                        final Deflater dflater = new Deflater(9, true);
                        dflater.setInput(byteArrUpdatedXml);
                        final byte[] dbuff = new byte[1024];
                        dflater.finish();

                        while (!dflater.finished()) {
                            int n = dflater.deflate(dbuff);
                            baosDeflate.write(dbuff, 0, n);
                        }

                        final byte[] byteArrDeflatedXml = baosDeflate.toByteArray();
                        dflater.end();

                        final long longUpdatedXmlDeflatedSize = (long) byteArrDeflatedXml.length;
                        lrCurrentRec.setLongUpdatedCompressedSize(longUpdatedXmlDeflatedSize);

                        // Calculate CRC32 checksum
                        final CRC32 crc32NewXml = new CRC32();
                        crc32NewXml.update(byteArrUpdatedXml);
                        final long lngCrc32NewXml = crc32NewXml.getValue();
                        lrCurrentRec.setLongUpdatedCrc32(lngCrc32NewXml);
                        lrCurrentRec.setByteArrModifiedRecord(byteArrDeflatedXml);
                    }
                } else {
                    //[Content_Types].xml is STORED, not DEFLATED
                    byteArrUpdatedXml = parseContentTypesXML(byteArrContent);
                    lrCurrentRec.setByteArrModifiedRecord(byteArrUpdatedXml);
                    
                    if (byteArrUpdatedXml.length == 0) {
                        lrCurrentRec.setByteArrModifiedRecord(byteArrUpdatedXml);  //size 0
                        lrCurrentRec.setByteArrInflatedRecord(byteArrContent);
                    } else {
                        final long longUpdatedXmlSize = (long) byteArrUpdatedXml.length;
                        lrCurrentRec.setLongUpdatedUncompressedSize(longUpdatedXmlSize);
                        lrCurrentRec.setLongUpdatedCompressedSize(longUpdatedXmlSize);
                        // Calculate CRC32 checksum
                        final CRC32 crc32NewXml = new CRC32();
                        crc32NewXml.update(byteArrUpdatedXml);
                        final long lngCrc32NewXml = crc32NewXml.getValue();
                        lrCurrentRec.setLongUpdatedCrc32(lngCrc32NewXml);
                        lrCurrentRec.setByteArrModifiedRecord(byteArrUpdatedXml);
                        lrCurrentRec.setByteArrInflatedRecord(byteArrUpdatedXml);
                    }
                }

                //Reconstruct [Content_Types].xml Local Record if changes were made
                final byte[] byteArrModifiedContentTypesRecord = lrCurrentRec.getByteArrModifiedRecord();
                final ByteArrayOutputStream baosReconstructContentTypesRecord = new ByteArrayOutputStream();
          
                boolean boolContentTypesChanged = false;
                byte[] byteArrReconstructedContentTypesRec;
              
                boolContentTypesChanged = true;
                //XML was modified. Reconstruct [Content_Types].xml Local Record
                baosReconstructContentTypesRecord.write(ZipUtil.intToLittleEndian(ZIP64_LOCAL_HEADER_MAGIC));

                // For [Content_Types].xml always set Ver needed = 2.0, General Purpose bit flag = 0 and remove data descriptor
                baosReconstructContentTypesRecord.write(ZipUtil.shortToLittleEndian(ZIP64_VERSION_NEEDED_20));
                baosReconstructContentTypesRecord.write(ZipUtil.shortToLittleEndian(ZIP64_GENERAL_PURPOSE_0));
                baosReconstructContentTypesRecord.write(ZipUtil.shortToLittleEndian(lrCurrentRec.getShortCompressMethod()));
                baosReconstructContentTypesRecord.write(ZipUtil.shortToLittleEndian(lrCurrentRec.getShortLastModTime()));
                baosReconstructContentTypesRecord.write(ZipUtil.shortToLittleEndian(lrCurrentRec.getShortLastModDate()));

                // If [Content_Types].xml was not modified, 
                if (byteArrModifiedContentTypesRecord.length == 0) {
                    // Get values from Data Descriptor if present
                    if (lrCurrentRec.getHasDataDescriptor()) {
                        baosReconstructContentTypesRecord.write(ZipUtil.intToLittleEndian(lrCurrentRec.getIntDdCrc32()));
                        baosReconstructContentTypesRecord.write(ZipUtil.intToLittleEndian((int)lrCurrentRec.getLongDdCompressedSize()));
                        baosReconstructContentTypesRecord.write(ZipUtil.intToLittleEndian((int)lrCurrentRec.getLongDdUncompressedSize()));
                    } else { // Otherwise, use values from standard header positions
                        baosReconstructContentTypesRecord.write(ZipUtil.intToLittleEndian(lrCurrentRec.getIntCrc32()));
                        baosReconstructContentTypesRecord.write(ZipUtil.intToLittleEndian(lrCurrentRec.getIntCompressedSize()));
                        baosReconstructContentTypesRecord.write(ZipUtil.intToLittleEndian(lrCurrentRec.getIntUncompressedSize()));
                    }
                } else { // If [Content_Types].xml was modified, use the newly calculated values
                    baosReconstructContentTypesRecord.write(ZipUtil.intToLittleEndian((int)lrCurrentRec.getLongUpdatedCrc32()));
                    baosReconstructContentTypesRecord.write(ZipUtil.intToLittleEndian((int)lrCurrentRec.getLongUpdatedCompressedSize()));
                    baosReconstructContentTypesRecord.write(ZipUtil.intToLittleEndian((int)lrCurrentRec.getLongUpdatedUncompressedSize()));
                }

                baosReconstructContentTypesRecord.write(ZipUtil.shortToLittleEndian(lrCurrentRec.getShortFilenameLen()));
                baosReconstructContentTypesRecord.write(ZipUtil.shortToLittleEndian(lrCurrentRec.getShortExtraFieldLen()));
                baosReconstructContentTypesRecord.write(lrCurrentRec.getByteArrFilename());
                baosReconstructContentTypesRecord.write(lrCurrentRec.getByteArrExtraField());
                if (byteArrModifiedContentTypesRecord.length > 0) {
                    baosReconstructContentTypesRecord.write(lrCurrentRec.getByteArrModifiedRecord());
                }
                else {
                    baosReconstructContentTypesRecord.write(byteArrContent);
                }
                  
                byteArrReconstructedContentTypesRec = baosReconstructContentTypesRecord.toByteArray();
                int intSizeReconstructedContentTypesRec = byteArrReconstructedContentTypesRec.length;
                
                outRaf.write(baosReconstructContentTypesRecord.toByteArray());
            } 
            catch(UnsupportedEncodingException | DataFormatException ex) {
                throw new IllegalRequestException(ex);
            }
        }
        return lrCurrentRec;
    }

    private static byte[] parseContentTypesXML(byte[] byteArrContentTypes) throws IllegalRequestException {
        try {
            InputStream inStreamContentTypes = new ByteArrayInputStream(byteArrContentTypes); 
            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();

            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
            docFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);

            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
            docFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

            // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
            docFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

            final DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
            final Document doc = docBuilder.parse(inStreamContentTypes);
            doc.setXmlStandalone(true);
            final Node nodeTypes = doc.getElementsByTagName("Types").item(0);
            final NodeList nodeListTypes = nodeTypes.getChildNodes();

            boolean hasAppxSignatureType = false;
            boolean hasCodeIntegrityType = false;

            for (int i = 0; i < nodeListTypes.getLength(); i++) {            
                Node node = nodeListTypes.item(i);

                if ("Override".equals(node.getNodeName())) {
                    NamedNodeMap attr = node.getAttributes();
                    Node nodeAttr = attr.getNamedItem("PartName");
                    String strFoundType = nodeAttr.getTextContent();

                    if (strFoundType.equals("/AppxSignature.p7x")) {
                        hasAppxSignatureType = true;
                    }
                    if (strFoundType.equals("/AppxMetadata/CodeIntegrity.cat")) {
                        hasCodeIntegrityType = true;
                    }
                }
            }

            if (!hasAppxSignatureType) {
                Element elt = doc.createElement("Override");
                elt.setAttribute("PartName", "/AppxSignature.p7x");
                elt.setAttribute("ContentType", "application/vnd.ms-appx.signature");
                nodeTypes.appendChild(elt);

            }
            
            if (!hasCodeIntegrityType) {
                Element elt = doc.createElement("Override");
                elt.setAttribute("PartName", "/AppxMetadata/CodeIntegrity.cat");
                elt.setAttribute("ContentType", "application/vnd.ms-pkiseccat");
                nodeTypes.appendChild(elt);
            }

            if (hasAppxSignatureType && hasCodeIntegrityType) {
                return new byte[0]; //return empty byte array if the XML already had AppxSignature.p7x and CodeIntegrity.cat types defined
            } else {
                // write the content into xml file
                final TransformerFactory transformerFactory = TransformerFactory.newInstance();
                final Transformer transformer = transformerFactory.newTransformer();
                transformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
                final DOMSource source = new DOMSource(doc);
                final ByteArrayOutputStream baosNewXml = new ByteArrayOutputStream();
                final StreamResult result = new StreamResult(baosNewXml);
                transformer.transform(source, result);
                byte[] baosUpdatedXml = baosNewXml.toByteArray();
                return baosUpdatedXml;
            }
        } catch (ParserConfigurationException | TransformerException | IOException | SAXException ex) {
            throw new IllegalRequestException("Unable to parse [Content_Types].xml", ex);
       }
    }

    public static class EocdField {

        final int ZIP64_EOCD_RECORD_SIGNATURE = 0x06064b50;
        final int ZIP64_EOCD_LOCATOR_MAGIC = 0x07064b50;

        public long longSizeOfEocd;
        public short shortVerMade;
        public short shortVerNeeded;
        public int intDiskNum;
        public int intDiskCd;
        public long longNumEntries;
        public long longTotalNumEntries;
        public long longCdSize;
        public long longCentralDirOffset;
        public int intZipExField1;         // 0x00000000
        public long longEocdOffset;        // EOCD offset
        public int intZipExField3;         // 0x01000000
        public int intEocdMagic;           // 0x504b0506
        public int intSignedAppxFlag;      // 0xffffffff (unsigned) 0x00000000 (signed)
        public int intZipExField6;         // 0xffffffff
        public int intZipExField7;         // 0xffffffff
        public int intZipExField8;         // 0xffffffff
        public short shortZipExEnd;        // 0x0000

        public byte[] getEocd() throws IOException {
            final ByteArrayOutputStream osEocd = new ByteArrayOutputStream();

            osEocd.write(ZipUtil.intToLittleEndian(this.ZIP64_EOCD_RECORD_SIGNATURE));
            osEocd.write(ZipUtil.longToLittleEndian(this.longSizeOfEocd));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortVerMade));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortVerNeeded));
            osEocd.write(ZipUtil.intToLittleEndian(this.intDiskNum));
            osEocd.write(ZipUtil.intToLittleEndian(this.intDiskCd));
            osEocd.write(ZipUtil.longToLittleEndian(this.longNumEntries));
            osEocd.write(ZipUtil.longToLittleEndian(this.longTotalNumEntries));
            osEocd.write(ZipUtil.longToLittleEndian(this.longCdSize));
            osEocd.write(ZipUtil.longToLittleEndian(this.longCentralDirOffset));
            osEocd.write(ZipUtil.intToLittleEndian(this.ZIP64_EOCD_LOCATOR_MAGIC));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField1));
            osEocd.write(ZipUtil.longToLittleEndian(this.longEocdOffset));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField3));
            osEocd.write(ZipUtil.intToLittleEndian(this.intEocdMagic));
            osEocd.write(ZipUtil.intToLittleEndian(this.intSignedAppxFlag));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField6));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField7));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField8));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortZipExEnd));

            return osEocd.toByteArray();
        }

        public byte[] getEocd(long cdSize, long cdOffset, long eocdOffset) throws IOException {
            final ByteArrayOutputStream osEocd = new ByteArrayOutputStream();

            osEocd.write(ZipUtil.intToLittleEndian(this.ZIP64_EOCD_RECORD_SIGNATURE));
            osEocd.write(ZipUtil.longToLittleEndian(this.longSizeOfEocd));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortVerMade));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortVerNeeded));
            osEocd.write(ZipUtil.intToLittleEndian(this.intDiskNum));
            osEocd.write(ZipUtil.intToLittleEndian(this.intDiskCd));
            osEocd.write(ZipUtil.longToLittleEndian(this.longNumEntries));
            osEocd.write(ZipUtil.longToLittleEndian(this.longTotalNumEntries));
            osEocd.write(ZipUtil.longToLittleEndian(cdSize));
            osEocd.write(ZipUtil.longToLittleEndian(cdOffset));
            osEocd.write(ZipUtil.intToLittleEndian(this.ZIP64_EOCD_LOCATOR_MAGIC));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField1));
            osEocd.write(ZipUtil.longToLittleEndian(eocdOffset));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField3));
            osEocd.write(ZipUtil.intToLittleEndian(this.intEocdMagic));
            osEocd.write(ZipUtil.intToLittleEndian(this.intSignedAppxFlag));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField6));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField7));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField8));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortZipExEnd));

            return osEocd.toByteArray();
        }


        public byte[] getEocdInitial(long cdSize, long cdOffset, long eocdOffset) throws IOException {
            final ByteArrayOutputStream osEocd = new ByteArrayOutputStream();

            osEocd.write(ZipUtil.intToLittleEndian(this.ZIP64_EOCD_RECORD_SIGNATURE));
            osEocd.write(ZipUtil.longToLittleEndian(this.longSizeOfEocd));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortVerMade));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortVerNeeded));
            osEocd.write(ZipUtil.intToLittleEndian(this.intDiskNum));
            osEocd.write(ZipUtil.intToLittleEndian(this.intDiskCd));
            osEocd.write(ZipUtil.longToLittleEndian(this.longNumEntries));
            osEocd.write(ZipUtil.longToLittleEndian(this.longTotalNumEntries));
            osEocd.write(ZipUtil.longToLittleEndian(cdSize));
            osEocd.write(ZipUtil.longToLittleEndian(cdOffset));
            osEocd.write(ZipUtil.intToLittleEndian(this.ZIP64_EOCD_LOCATOR_MAGIC));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField1));
            osEocd.write(ZipUtil.longToLittleEndian(eocdOffset));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField3));
            osEocd.write(ZipUtil.intToLittleEndian(this.intEocdMagic));
            osEocd.write(ZipUtil.intToLittleEndian(0)); //Signed Flag
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField6));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField7));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField8));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortZipExEnd));

            return osEocd.toByteArray();
        }

        public byte[] getEocdFinal(long cdSize, long cdOffset, long eocdOffset) throws IOException {
            final ByteArrayOutputStream osEocd = new ByteArrayOutputStream();

            osEocd.write(ZipUtil.intToLittleEndian(this.ZIP64_EOCD_RECORD_SIGNATURE));
            osEocd.write(ZipUtil.longToLittleEndian(this.longSizeOfEocd));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortVerMade));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortVerNeeded));
            osEocd.write(ZipUtil.intToLittleEndian(this.intDiskNum));
            osEocd.write(ZipUtil.intToLittleEndian(this.intDiskCd));
            osEocd.write(ZipUtil.longToLittleEndian(this.longNumEntries+1));
            osEocd.write(ZipUtil.longToLittleEndian(this.longTotalNumEntries+1));
            osEocd.write(ZipUtil.longToLittleEndian(cdSize));
            osEocd.write(ZipUtil.longToLittleEndian(cdOffset));
            osEocd.write(ZipUtil.intToLittleEndian(this.ZIP64_EOCD_LOCATOR_MAGIC));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField1));
            osEocd.write(ZipUtil.longToLittleEndian(eocdOffset));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField3));
            osEocd.write(ZipUtil.intToLittleEndian(this.intEocdMagic));
            osEocd.write(ZipUtil.intToLittleEndian(0)); //Signed Flag
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField6));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField7));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField8));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortZipExEnd));

            return osEocd.toByteArray();
        }

        public byte[] getEocdVerify(long cdSize, long cdOffset, long eocdOffset) throws IOException {

            ByteArrayOutputStream osEocd = new ByteArrayOutputStream();

            osEocd.write(ZipUtil.intToLittleEndian(this.ZIP64_EOCD_RECORD_SIGNATURE));
            osEocd.write(ZipUtil.longToLittleEndian(this.longSizeOfEocd));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortVerMade));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortVerNeeded));
            osEocd.write(ZipUtil.intToLittleEndian(this.intDiskNum));
            osEocd.write(ZipUtil.intToLittleEndian(this.intDiskCd));
            osEocd.write(ZipUtil.longToLittleEndian(this.longNumEntries-1));
            osEocd.write(ZipUtil.longToLittleEndian(this.longTotalNumEntries-1));
            osEocd.write(ZipUtil.longToLittleEndian(cdSize));
            osEocd.write(ZipUtil.longToLittleEndian(cdOffset));
            osEocd.write(ZipUtil.intToLittleEndian(this.ZIP64_EOCD_LOCATOR_MAGIC));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField1));
            osEocd.write(ZipUtil.longToLittleEndian(eocdOffset));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField3));
            osEocd.write(ZipUtil.intToLittleEndian(this.intEocdMagic));
            osEocd.write(ZipUtil.intToLittleEndian(0)); //Signed Flag
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField6));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField7));
            osEocd.write(ZipUtil.intToLittleEndian(this.intZipExField8));
            osEocd.write(ZipUtil.shortToLittleEndian(this.shortZipExEnd));

            return osEocd.toByteArray();
        }
    }

    /**
     * Wrapper for central directory offset
     *
     */
    public static class CentralDirectoryOffset {

        private long longCentralDirOffset;

        public CentralDirectoryOffset(long centralDirOffset) {
            this.longCentralDirOffset = centralDirOffset;
        }

        public CentralDirectoryOffset() {
            this.longCentralDirOffset = 0;
        }
        

        public long getCentralDirOffset() {
            return this.longCentralDirOffset;
        }

        public void setCentralDirOffset(long centralDirOffset) {
            this.longCentralDirOffset = centralDirOffset;
        }

    }
}
