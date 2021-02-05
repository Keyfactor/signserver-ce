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
import java.util.Optional;
import java.util.jar.JarInputStream;
import java.util.zip.ZipEntry;
import org.signserver.client.cli.defaultimpl.DocumentSignerFactory;

/**
 * Version of the FileSpecificHandlerFactory that can create FileSpecificHandlerS
 * capable of performing client-side hashing and construction of certain formats.
 *
 * @author Marcus Lundblad
 * @author Markus Kilås
 * @author Selwyn Oh
 * @version $Id$
 */
public class EnterpriseFileSpecificHandlerFactory implements FileSpecificHandlerFactory {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(EnterpriseFileSpecificHandlerFactory.class);

    private static enum FileType {
        /** Portable executable. */
        PE,
        
        /** Windows installer. */
        MSI,
        
        /** ZIP file (could be a JAR). */
        ZIP,
        
        PGP,

        /** DPKG-SIG (.deb packages verifiable with the dpkg-sig tool). */
        DPKG_SIG,

        /** APPX or APPX Bundle. */
        APPX,

        /** DNS Zone File in "Zone ZIP" format. */
        ZONE_ZIP,

        /** Android packages. */
        APK,
        
        /** PowerShell. */
        PS1,
    }

    
    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide, Map<String, String> extraOptions) throws IOException {
        if (clientSide) {
            final FileType type = getTypeOfFile(inFile);

            return createHandler(type, inFile, outFile, extraOptions,
                                 Optional.empty(), Optional.empty(), null, null,
                                 null);
        } else {
            return new StraightFileSpecificHandler(new FileInputStream(inFile),
                                                   inFile.length());
        }
    }

    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final String workerName) throws IOException {
        return createHandler(inFile, outFile, clientSide, extraOptions,
                             workerName, null, null, null);
    }

    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final String workerName,
                                             final DocumentSignerFactory signerFactory,
                                             final Map<String, Object> requestContext,
                                             final Map<String, String> metadata)
            throws IOException {
        if (clientSide) {
            final FileType type = getTypeOfFile(inFile);

            return createHandler(type, inFile, outFile, extraOptions,
                                 Optional.of(workerName), Optional.empty(),
                                 signerFactory, requestContext, metadata);
        } else {
            return new StraightFileSpecificHandler(new FileInputStream(inFile),
                                                   inFile.length());
        }
    }

    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final int workerId) throws IOException {
        return createHandler(inFile, outFile, clientSide, extraOptions,
                             workerId, null, null, null);
    }

    @Override
    public FileSpecificHandler createHandler(final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final int workerId,
                                             final DocumentSignerFactory signerFactory,
                                             final Map<String, Object> requestContext,
                                             final Map<String, String> metadata)
            throws IOException {
        if (clientSide) {
            final FileType type = getTypeOfFile(inFile);
        
            return createHandler(type, inFile, outFile, extraOptions,
                                 Optional.empty(), Optional.of(workerId),
                                 signerFactory, requestContext, metadata);
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

            return createHandler(type, inFile, outFile, extraOptions,
                                 Optional.empty(), Optional.empty(), null, null,
                                 null);
        } else {
            return new StraightFileSpecificHandler(new FileInputStream(inFile),
                                                   inFile.length());
        }
    }

    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final String workerName)
            throws IOException {
        return createHandler(fileType, inFile, outFile, clientSide, extraOptions,
                             workerName, null, null, null);
    }

    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final String workerName,
                                             final DocumentSignerFactory signerFactory,
                                             final Map<String, Object> requestContext,
                                             final Map<String, String> metadata)
            throws IOException {
        if (clientSide) {
            final FileType type = FileType.valueOf(fileType.toUpperCase(Locale.ENGLISH));

            return createHandler(type, inFile, outFile, extraOptions,
                                 Optional.of(workerName), Optional.empty(),
                                 signerFactory, requestContext, metadata);
        } else {
            return new StraightFileSpecificHandler(new FileInputStream(inFile),
                                                   inFile.length());
        }
    }

    @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final int workerId)
            throws IOException {
        return createHandler(fileType, inFile, outFile, clientSide, extraOptions,
                             workerId, null, null, null);
    }

     @Override
    public FileSpecificHandler createHandler(final String fileType,
                                             final File inFile, final File outFile,
                                             final boolean clientSide,
                                             final Map<String, String> extraOptions,
                                             final int workerId,
                                             final DocumentSignerFactory signerFactory,
                                             final Map<String, Object> requestContext,
                                             final Map<String, String> metadata)
            throws IOException {
        if (clientSide) {
            final FileType type = FileType.valueOf(fileType.toUpperCase(Locale.ENGLISH));

            return createHandler(type, inFile, outFile, extraOptions,
                                 Optional.empty(), Optional.of(workerId),
                                 signerFactory, requestContext, metadata);
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
                                              final Map<String, String> extraOptions,
                                              final Optional<String> workerName,
                                              final Optional<Integer> workerId,
                                              final DocumentSignerFactory signerFactory,
                                              final Map<String, Object> requestContext,
                                              final Map<String, String> metadata) {
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
            case PS1:
                return new Ps1FileSpecificHandler(inFile, outFile);
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

            case ZONE_ZIP:
                final String forceResignValue = extraOptions.get("FORCE_RESIGN");
                final String zoneName = extraOptions.get("ZONE_NAME");
                final boolean forceResign;
                final String minRemainingValidityValue = extraOptions.get("MIN_REMAINING_VALIDITY");
                Long minRemainingValidity = null;
                if (forceResignValue != null && forceResignValue.trim().equalsIgnoreCase("TRUE")) {
                    forceResign = true;
                } else if (forceResignValue != null && forceResignValue.trim().equalsIgnoreCase("FALSE")) {
                    forceResign = false;
                } else if (forceResignValue != null) {
                    throw new IllegalArgumentException("Incorrect value for FORCE_RESIGN");
                } else {
                    forceResign = false;
                }
                if (zoneName == null) {
                    throw new IllegalArgumentException("Missing ZONE_NAME extraoption");
                }
                
                if (forceResign == false && minRemainingValidityValue != null) {
                    try {
                        // MIN_REMAINING_VALIDITY specified in seconds
                        // convert in into milliseconds
                        minRemainingValidity = (Long.valueOf(minRemainingValidityValue)) * 1000;
                    } catch (NumberFormatException ex) {
                        throw new IllegalArgumentException("Invalid value for MIN_REMAINING_VALIDITY extraoption");
                    }
                }
                              
                return new ZoneFileSpecificHandler(inFile, outFile, forceResign,
                        zoneName, minRemainingValidity);
            case APK:
                if (signerFactory == null) {
                    throw new IllegalArgumentException("Must provide a DocumentSignerFactory for APK signing");
                }
                if (requestContext == null) {
                    throw new IllegalArgumentException("Must provide a request context for APK signing");
                }
                if (workerName.isPresent()) {
                    return new ApkFileSpecificHandler(inFile, outFile,
                                                      signerFactory,
                                                      requestContext,
                                                      metadata,
                                                      workerName.get(),
                                                      extraOptions);
                } else if (workerId.isPresent()) {
                    return new ApkFileSpecificHandler(inFile, outFile,
                                                      signerFactory,
                                                      requestContext,
                                                      metadata,
                                                      workerId.get(),
                                                      extraOptions);
                } else {
                    throw new IllegalArgumentException("Need worker name or ID with APK");
                }
            default:
                throw new IllegalArgumentException("Unknown file type");
        }
    }
    
    /**
     * Determine the file type based on "magic bytes".
     * Copied from MSAuthCodeSigner: TODO: might refactor this out (along with the
     * file type enum).
     * 
     * @param inFile in file
     * @return file type (PE or MSI)
     */
    private FileType getTypeOfFile(final File inFile)
        throws FileNotFoundException, IOException {

        FileType type;
        try (final InputStream in =
                new BufferedInputStream(new FileInputStream(inFile))) {
            final byte[] magic = new byte[8];

            if (LOG.isDebugEnabled()) {
                LOG.debug("Input stream: " + in.getClass().getName());
            }

            //XXX: This was removed by APPX merge: in.mark(8);

            int bytesRead = in.read(magic, 0, 8);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Bytes read: " + bytesRead);
            }

            if (inFile.getName().toUpperCase(Locale.ENGLISH).endsWith(".PS1")
                    || inFile.getName().toUpperCase(Locale.ENGLISH).endsWith(".PSD1")
                    || inFile.getName().toUpperCase(Locale.ENGLISH).endsWith(".PSM1")) {
                type = FileType.PS1;
            } else if (bytesRead >= 2 && magic[0] == 'M' && magic[1] == 'Z') {
                type = FileType.PE;
            } else if (bytesRead >= 8 &&
                       magic[0] == (byte) 0xD0 && magic[1] == (byte) 0xCF &&
                       magic[2] == (byte) 0x11 && magic[3] == (byte) 0xE0 &&
                       magic[4] == (byte) 0xA1 && magic[5] == (byte) 0xB1 &&
                       magic[6] == (byte) 0x1A && magic[7] == (byte) 0xE1) {
                type = FileType.MSI;
            } else if (bytesRead >= 2 && magic[0] == 'P' && magic[1] == 'K') {
                type = FileType.ZIP;

                // APPX: verify the rest of the local file header signature
                if (bytesRead >= 4 && magic[2] == 0x03 && magic[3] == 0x04) {

                    // Alternating buffer to store trailing 22 bytes
                    final byte[][] buffer = new byte[2][4096];

                    // XXX: This reads through the entire file we might want to instead use a RandomAccessFile and seek directly to the end
                    int intRead = 0;
                    int counter = 0;
                    while (-1 != intRead && (intRead == 4096 || intRead == 0)) {
                        int buffSwitch = counter++ % 2;
                        if (buffSwitch == 0) {
                            intRead = in.read(buffer[0]);
                        }
                        else {
                            intRead = in.read(buffer[1]);
                        }
                    }

                    int whichBuf = (counter - 1) % 2;

                    if (LOG.isTraceEnabled()) {
                        LOG.trace("buffer 1: " + Hex.encodeHexString(buffer[0]));
                        LOG.trace("buffer 2: " + Hex.encodeHexString(buffer[1]));
                        LOG.trace("counter: " + counter);
                        LOG.trace("whichBuf: " + whichBuf);
                    }

                    byte[] trailingBytes;
                    if (intRead != -1) {
                        if (whichBuf == 0) {
                            trailingBytes = Arrays.copyOfRange(buffer[0], 0, intRead);
                            if (LOG.isTraceEnabled()) {
                                LOG.trace("Last in buffer 1: " + Hex.encodeHexString(trailingBytes));
                            }
                        }
                        else {
                            trailingBytes = Arrays.copyOfRange(buffer[1], 0, intRead);
                            if (LOG.isTraceEnabled()) {
                                LOG.trace("Last in buffer 2: " + Hex.encodeHexString(trailingBytes));
                            }
                        }
                        if (trailingBytes.length < 22) {
                            if (counter >= 2) {
                                final ByteArrayOutputStream combine = new ByteArrayOutputStream();
                                final int diff = 22 - trailingBytes.length;
                                if (LOG.isTraceEnabled()) {
                                    LOG.trace("Test Len = " + trailingBytes.length);
                                }
                                if (whichBuf == 0) {
                                    combine.write(buffer[1], 4096 - diff, diff);
                                    combine.write(buffer[0], 0, intRead);
                                }
                                else {
                                    combine.write(buffer[0], 4096 - diff, diff);
                                    combine.write(buffer[1], 0, intRead);
                                }
                                type = hasAppxTrailer(combine.toByteArray()) ? FileType.APPX : FileType.ZIP;
                                if (LOG.isTraceEnabled()) {
                                    LOG.trace("Combined : " + Hex.encodeHexString(combine.toByteArray()));
                                }
                            }
                        } else {
                            type = hasAppxTrailer(trailingBytes) ? FileType.APPX : FileType.ZIP; 
                        }
                    } else {
                        // last successful read
                        if (whichBuf == 0) {
                            trailingBytes = Arrays.copyOfRange(buffer[1], 0, 4096);
                            if (LOG.isTraceEnabled()) {
                                LOG.trace("intRead was -1 Last in buffer 2: " + Hex.encodeHexString(trailingBytes));
                            }
                        }
                        else {
                            trailingBytes = Arrays.copyOfRange(buffer[0], 0, 4096);
                            if (LOG.isTraceEnabled()) {
                                LOG.trace("intRead was -1 Last in buffer 1: " + Hex.encodeHexString(trailingBytes));
                            }
                        }
                        type = hasAppxTrailer(trailingBytes) ? FileType.APPX : FileType.ZIP;
                    }
                    LOG.debug("Type: " + type);
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
        }

        // if type is ZIP, try parsing it as an APK
        if (type == FileType.ZIP) {
            try (final JarInputStream jis =
                    new JarInputStream(new FileInputStream(inFile))) {
                ZipEntry entry;

                while ((entry = jis.getNextEntry()) != null) {
                    if ("AndroidManifest.xml".equals(entry.getName())) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Found Android manifest file in JAR");
                        }
                        type = FileType.APK;
                        break;
                    }
                }
            }
        }

        //XXX: This was removed by APPX merge: in.reset();
        return type;
    }

    /**
     * Determine APPX file type based on "magic bytes".
     * 
     * @param trailingBytes byte array containing trailing bytes of file
     * @return true if the trailing bytes match the signature of an APPX file, otherwise false
     */
    public boolean hasAppxTrailer(final byte[] trailingBytes) {
        final int len = trailingBytes.length;
        return len >= 22 && ( 
            (trailingBytes[len - 22] == (byte) 0x50 && trailingBytes[len - 21] == (byte) 0x4B &&
            trailingBytes[len - 20] == (byte) 0x05 && trailingBytes[len - 19] == (byte) 0x06 &&
            trailingBytes[len - 18] == (byte) 0xFF && trailingBytes[len - 17] == (byte) 0xFF &&
            trailingBytes[len - 16] == (byte) 0xFF && trailingBytes[len - 15] == (byte) 0xFF &&
            trailingBytes[len - 14] == (byte) 0xFF && trailingBytes[len - 13] == (byte) 0xFF &&
            trailingBytes[len - 12] == (byte) 0xFF && trailingBytes[len - 11] == (byte) 0xFF &&
            trailingBytes[len - 10] == (byte) 0xFF && trailingBytes[len - 9]  == (byte) 0xFF &&
            trailingBytes[len - 8]  == (byte) 0xFF && trailingBytes[len - 7]  == (byte) 0xFF &&
            trailingBytes[len - 6]  == (byte) 0xFF && trailingBytes[len - 5]  == (byte) 0xFF &&
            trailingBytes[len - 4]  == (byte) 0xFF && trailingBytes[len - 3]  == (byte) 0xFF &&
            trailingBytes[len - 2]  == (byte) 0x00 && trailingBytes[len - 1]  == (byte) 0x00) 
                
                || 
            
            (trailingBytes[len - 22] == (byte) 0x50 && trailingBytes[len - 21] == (byte) 0x4B &&
            trailingBytes[len - 20] == (byte) 0x05 && trailingBytes[len - 19] == (byte) 0x06 &&
            trailingBytes[len - 18] == (byte) 0x00 && trailingBytes[len - 17] == (byte) 0x00 &&
            trailingBytes[len - 16] == (byte) 0x00 && trailingBytes[len - 15] == (byte) 0x00 &&
            trailingBytes[len - 14] == (byte) 0xFF && trailingBytes[len - 13] == (byte) 0xFF &&
            trailingBytes[len - 12] == (byte) 0xFF && trailingBytes[len - 11] == (byte) 0xFF &&
            trailingBytes[len - 10] == (byte) 0xFF && trailingBytes[len - 9]  == (byte) 0xFF &&
            trailingBytes[len - 8]  == (byte) 0xFF && trailingBytes[len - 7]  == (byte) 0xFF &&
            trailingBytes[len - 6]  == (byte) 0xFF && trailingBytes[len - 5]  == (byte) 0xFF &&
            trailingBytes[len - 4]  == (byte) 0xFF && trailingBytes[len - 3]  == (byte) 0xFF &&
            trailingBytes[len - 2]  == (byte) 0x00 && trailingBytes[len - 1]  == (byte) 0x00));
    }

}
