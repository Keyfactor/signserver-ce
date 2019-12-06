/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.client.cli.enterprise;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.signserver.client.cli.defaultimpl.FileSpecificHandler;
import org.signserver.client.cli.defaultimpl.StraightFileSpecificHandler;
import org.signserver.client.cli.spi.FileSpecificHandlerFactory;
import org.signserver.module.jarchive.signer.JArchiveOptions;
import org.signserver.module.jarchive.signer.JArchiveSigner;
import java.util.Arrays;
import java.io.ByteArrayOutputStream;

/**
 * Version of the FileSpecificHandlerFactory that can create FileSpecificHandlerS
 * capable of performing client-side hashing and contruction of certain formats.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class EnterpriseFileSpecificHandlerFactory implements FileSpecificHandlerFactory {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(EnterpriseFileSpecificHandlerFactory.class);

    private static enum FileType {
        /** Portable executable */
        PE,
        
        /** Windows installer */
        MSI,
        
        /** ZIP file (could be a JAR). */
        ZIP,
        
        PGP,

        /** DPKG-SIG (.deb packages verifiable with the dpkg-sig tool) */
        DPKG_SIG,

        /** Appx or Appx Bundle */
        APPX
    }

    
    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide, Map<String, String> extraOptions) throws IOException {
        if (clientSide) {
            final FileType type = getTypeOfFile(new BufferedInputStream(new FileInputStream(inFile)));
        
            return createHandler(type, inFile, outFile, extraOptions);
        } else {
            return new StraightFileSpecificHandler(new FileInputStream(inFile),
                                                   inFile.length());
        }
    }
    
    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile, final File outFile,
                                             final boolean clientSide, Map<String, String> extraOptions)
            throws IOException {
        if (clientSide) {
            final FileType type = FileType.valueOf(fileType.toUpperCase(Locale.ENGLISH));

            return createHandler(type, inFile, outFile, extraOptions);
        } else {
            return new StraightFileSpecificHandler(new FileInputStream(inFile),
                                                   inFile.length());
        }
    }

    @Override
    public FileSpecificHandler createHandler(final InputStream inStream,
                                             final long size,
                                             final File outFile,
                                             final boolean clientSide, Map<String, String> extraOptions) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final InputStream inStream,
                                             final long size,
                                             final File outFile,
                                             final boolean clientSide, Map<String, String> extraOptions) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public boolean canCreateClientSideCapableHandler() {
        return true;
    }
    
    @Override
    public boolean canHandleFileType(String fileType) {
        try {
            final FileType type = FileType.valueOf(fileType.toUpperCase());
            
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private long parseKeyIdOptionValue(final String keyIdValue) {
        final long keyId;
        
        if (keyIdValue != null) {
            try {
                keyId = new BigInteger(keyIdValue, 16).longValue();
            } catch (NumberFormatException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Exception when parsing key ID: " +
                              e.getMessage());
                }
                throw new IllegalArgumentException("Failed to parse key ID: " +
                                                   keyIdValue);
            }
        } else {
            keyId = 0;
        }

        return keyId;
    }

    private int parseKeyAlgorithmOptionValue(final String keyAlgorithmValue) {
        final int keyAlgorithm;

        if (keyAlgorithmValue != null) {
            switch (keyAlgorithmValue.toUpperCase(Locale.ENGLISH)) {
                case "RSA":
                    keyAlgorithm = PublicKeyAlgorithmTags.RSA_SIGN;
                    break;
                case "DSA":
                    keyAlgorithm = PublicKeyAlgorithmTags.DSA;
                    break;
                case "ECDSA":
                    keyAlgorithm = PublicKeyAlgorithmTags.ECDSA;
                    break;
                default:
                    try {
                        keyAlgorithm =
                                Integer.parseInt(keyAlgorithmValue);
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException("Unsupported key algorithm: " +
                                    keyAlgorithmValue);
                    }
            }
        } else {
            keyAlgorithm = PublicKeyAlgorithmTags.RSA_SIGN;
        }

        return keyAlgorithm;
    }

    private byte[] parseFingerprintOptionValue(final String fingerprintOptionValue) {
        if (fingerprintOptionValue != null) {
            try {
                return Hex.decodeHex(fingerprintOptionValue.toCharArray());
            } catch (DecoderException e) {
                throw new IllegalArgumentException("Failed to parse fingerprint: " +
                                               fingerprintOptionValue, e);
            }
        } else {
            return Long.toHexString(0).getBytes(StandardCharsets.US_ASCII);
        }
    }
    
    private FileSpecificHandler createHandler(final FileType type,
                                              final File inFile,
                                              final File outFile,
                                              final Map<String, String> extraOptions) {
        String keyIdValue;
        String keyAlgorithmValue;
        String fingerprintValue;
        long keyId;
        int keyAlgorithm;
        byte[] fingerprint;

        switch (type) {
            case PE:
                return new PEFileSpecificHandler(inFile, outFile);
            case MSI:
                return new MSIFileSpecificHandler(inFile, outFile);
            case PGP:
                final String outputFormatValue =
                        extraOptions.get("RESPONSE_FORMAT");
                final String detachedValue =
                        extraOptions.get("DETACHED_SIGNATURE");
                
                final OpenPGPSpecificFileHandler.OutputFormat outputFormat;
                final boolean detached;

                keyIdValue = extraOptions.get("KEY_ID");
                keyAlgorithmValue = extraOptions.get("KEY_ALGORITHM");
                keyId = parseKeyIdOptionValue(keyIdValue);
                keyAlgorithm = parseKeyAlgorithmOptionValue(keyAlgorithmValue);

                if (outputFormatValue != null) {
                    try {
                        outputFormat =
                                OpenPGPSpecificFileHandler.OutputFormat.valueOf(outputFormatValue.toUpperCase(Locale.ENGLISH));
                    } catch (IllegalArgumentException e) {
                        throw new IllegalArgumentException("Unsupported output format: " +
                                outputFormatValue);
                    }
                } else {
                    outputFormat =
                            OpenPGPSpecificFileHandler.OutputFormat.ARMORED;
                }

                if (detachedValue == null) {
                    throw new IllegalArgumentException("Need to specify -extraoption DETACHED_SIGNATURE=true/false");
                } else {
                    if (Boolean.FALSE.toString().equalsIgnoreCase(detachedValue)) {
                        detached = false;
                        if (outputFormat == OpenPGPSpecificFileHandler.OutputFormat.BINARY) {
                            throw new IllegalArgumentException("-extraoption RESPONSE_FORMAT= can be only set as " +
                                                               OpenPGPSpecificFileHandler.OutputFormat.ARMORED.toString() +
                                                               " when -extraoption DETACHED_SIGNATURE=FALSE is specified");
                        }
                    } else if (Boolean.TRUE.toString().equalsIgnoreCase(detachedValue)) {
                        detached = true;
                    } else {
                        throw new IllegalArgumentException("Incorrect value for -extraoption DETACHED_SIGNATURE= . Expecting TRUE or FALSE.");
                    }
                }

                return new OpenPGPSpecificFileHandler(inFile, outFile, keyId,
                                                      keyAlgorithm, outputFormat,
                                                      detached);
            case DPKG_SIG:
                keyIdValue = extraOptions.get("KEY_ID");
                fingerprintValue = extraOptions.get("KEY_FINGERPRINT");
                keyAlgorithmValue = extraOptions.get("KEY_ALGORITHM");

                keyId = parseKeyIdOptionValue(keyIdValue);
                fingerprint = parseFingerprintOptionValue(fingerprintValue);
                keyAlgorithm = parseKeyAlgorithmOptionValue(keyAlgorithmValue);
                
                return new DpkgSigFileSpecificHandler(inFile, outFile, keyId,
                                                      fingerprint, keyAlgorithm);
            case ZIP:
                // Only supported name type as KEYALIAS not available on client-side
                extraOptions.put("SIGNATURE_NAME_TYPE", JArchiveSigner.SignatureNameType.VALUE.name());
                String signatureNameValue = extraOptions.get("SIGNATURE_NAME_VALUE");
                if (signatureNameValue == null || signatureNameValue.trim().isEmpty()) {
                    extraOptions.put("SIGNATURE_NAME_VALUE", "SIGNSERV");
                }
                
                // Parse the options
                JArchiveOptions options = new JArchiveOptions(extraOptions);
                if (!options.getConfigErrors().isEmpty()) {
                    throw new IllegalArgumentException("Incorrect JAR signer options: " + options.getConfigErrors());
                }
                long timestamp = System.currentTimeMillis();

                return new JarFileSpecificHandler(inFile, outFile, options.isZipAlign() ? 4 : 0, options.isKeepSignatures(), options.isReplaceSignature(), options.getSignatureNameValue(), timestamp);
            case APPX:
                return new AppxFileSpecificHandler(inFile, outFile);    
            default:
                throw new IllegalArgumentException("Unknown file type");
        }
    }
    
    /**
     * Determine the file type based on "magic bytes".
     * Copied from MSAuthCodeSigner: TODO: might refactor this out (along with the
     * file type enum).
     * 
     * @param input stream
     * @return file type (PE or MSI)
     */
    private FileType getTypeOfFile(final InputStream in)
        throws FileNotFoundException, IOException {
        
        final byte[] magic = new byte[8];
        FileType type;
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Input stream: " + in.getClass().getName());
        }
        
        //XXX: This was removed by APPX merge: in.mark(8);
        
        int bytesRead = in.read(magic, 0, 8);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Bytes read: " + bytesRead);
        }
        
        if (bytesRead >= 2 && magic[0] == 'M' && magic[1] == 'Z') {
            type = FileType.PE;
        } else if (bytesRead >= 8 &&
                   magic[0] == (byte) 0xD0 && magic[1] == (byte) 0xCF &&
                   magic[2] == (byte) 0x11 && magic[3] == (byte) 0xE0 &&
                   magic[4] == (byte) 0xA1 && magic[5] == (byte) 0xB1 &&
                   magic[6] == (byte) 0x1A && magic[7] == (byte) 0xE1) {
            type = FileType.MSI;
        } else if (bytesRead >= 2 && magic[0] == 'P' && magic[1] == 'K') {
            type = FileType.ZIP;


            //Appx: verify the rest of the local file header signature
            if (bytesRead >= 4 && magic[2] == 0x03 && magic[3] == 0x04) {

                //alternating buffer to store trailing 22 bytes
                byte[][] buffer = new byte[2][4096];

                //BufferedInputStream bis = new BufferedInputStream(in);
                
                int intRead = 0;
                int counter = 0;

                while (-1 != intRead && (intRead == 4096 || intRead ==0)){

                    int buffSwitch = counter++ % 2;
                    if (buffSwitch == 0) {
                        intRead = in.read(buffer[0]);
                    }
                    else {
                        intRead = in.read(buffer[1]);
                    }

                }

                LOG.debug("buffer 1: " + Hex.encodeHexString(buffer[0]));
                LOG.debug("buffer 2: " + Hex.encodeHexString(buffer[1]));
                LOG.debug("counter: " + counter);
                int whichBuf = (counter - 1) % 2;
                byte[] byteArrTrailing = new byte[0];
                if (intRead != -1) {
                    
                    if (whichBuf == 0){
                        byteArrTrailing = Arrays.copyOfRange(buffer[0],0,intRead);
                        LOG.debug("Last in buffer 1: " + Hex.encodeHexString(byteArrTrailing));
                    }
                    else {
                        byteArrTrailing = Arrays.copyOfRange(buffer[1],0,intRead);
                        LOG.debug("Last in buffer 2: " + Hex.encodeHexString(byteArrTrailing));
                    }
                    if (byteArrTrailing.length < 22) {
                        if (counter >= 2) {
                            ByteArrayOutputStream combine = new ByteArrayOutputStream();
                            int diff = 22 - byteArrTrailing.length;
                            LOG.debug("Test Len = " + byteArrTrailing.length);
                            if (whichBuf == 0) {
                                combine.write(buffer[1], 4096-diff, diff);
                                combine.write(buffer[0],0,intRead);
                            }
                            else {
                                combine.write(buffer[0], 4096-diff, diff);
                                combine.write(buffer[1],0,intRead);
                            }
                            LOG.debug("Combined : " + Hex.encodeHexString(combine.toByteArray()));
                            LOG.debug("isAppxFile: " + isAppxFile(combine.toByteArray()));
                            type = isAppxFile(combine.toByteArray()) ? FileType.APPX : FileType.ZIP;
                        }
                    } 
                    else {
                        LOG.debug("isAppxFile: " + isAppxFile(byteArrTrailing));
                        type = isAppxFile(byteArrTrailing) ? FileType.APPX : FileType.ZIP; 
                    }
                }
                else {
                    //last successful read
                    if (whichBuf == 0){
                        byteArrTrailing = Arrays.copyOfRange(buffer[1],0,4096);
                        LOG.debug("intRead was -1 Last in buffer 2: " + Hex.encodeHexString(byteArrTrailing));

                    }
                    else {
                        byteArrTrailing = Arrays.copyOfRange(buffer[0],0,4096);
                        LOG.debug("intRead was -1 Last in buffer 1: " + Hex.encodeHexString(byteArrTrailing));
                    }
                    LOG.debug(isAppxFile(byteArrTrailing));
                    type = isAppxFile(byteArrTrailing) ? FileType.APPX : FileType.ZIP;
                }
            }

        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unsupported file type");
                if (bytesRead > 0) {
                    final StringBuilder sb = new StringBuilder();
                    
                    sb.append("Content: ");
                    for (int i = 0; i < bytesRead; i++) {
                        sb.append(String.format("%02X ", magic[i]));
                    }
                    LOG.debug(sb.toString());
                }
            }
            
            throw new IllegalArgumentException("Unsupported file type");
        }
        
        //XXX: This was removed by APPX merge: in.reset();
        return type;
    }

    /**
     * Determine Appx file type based on "magic bytes".
     * 
     * @param trailingBytes byte array containing trailing bytes of file
     * @return true is the trailng bytes match the signature of an Appx file, otherwise false
     */
    public boolean isAppxFile(final byte[] trailingBytes) {
        int len = trailingBytes.length;
        if (len >= 22 &&
                   trailingBytes[len - 22] == (byte) 0x50 && trailingBytes[len - 21] == (byte) 0x4B &&
                   trailingBytes[len - 20] == (byte) 0x05 && trailingBytes[len - 19] == (byte) 0x06 &&
                   trailingBytes[len - 18] == (byte) 0xFF && trailingBytes[len - 17] == (byte) 0xFF &&
                   trailingBytes[len - 16] == (byte) 0xFF && trailingBytes[len - 15] == (byte) 0xFF &&
                   trailingBytes[len - 14] == (byte) 0xFF && trailingBytes[len - 13] == (byte) 0xFF &&
                   trailingBytes[len - 12] == (byte) 0xFF && trailingBytes[len - 11] == (byte) 0xFF &&
                   trailingBytes[len - 10] == (byte) 0xFF && trailingBytes[len - 9]  == (byte) 0xFF &&
                   trailingBytes[len - 8]  == (byte) 0xFF && trailingBytes[len - 7]  == (byte) 0xFF &&
                   trailingBytes[len - 6]  == (byte) 0xFF && trailingBytes[len - 5]  == (byte) 0xFF &&
                   trailingBytes[len - 4]  == (byte) 0xFF && trailingBytes[len - 3]  == (byte) 0xFF &&
                   trailingBytes[len - 2]  == (byte) 0x00 && trailingBytes[len - 1]  == (byte) 0x00) {
            return true;
        }
        else {
            return false;
        }
    }

}
