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

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * An AR file directly parsed from the provided input stream.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ParsedArFile {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ParsedArFile.class);

    private static final String MAGIC = "!<arch>\n";

    private final ArrayList<Entry> entries;

    public ParsedArFile(ArrayList<Entry> entries) {
        this.entries = entries;
    }
    
    public static ParsedArFile parse(InputStream in) throws IOException, OperatorCreationException {
        return parseCopyAndHash(in, new NullOutputStream());
    }

    public static ParsedArFile parseCopyAndHash(InputStream in, OutputStream copyOut, AlgorithmIdentifier... digestAlgorithms) throws IOException, OperatorCreationException {
        final DataInputStream din;
        if (in instanceof DataInputStream) {
            din = (DataInputStream) in;
        } else {
            din = new DataInputStream(in);
        }

        // Read magic
        final byte[] magicBytes = new byte[MAGIC.length()];
        din.readFully(magicBytes);
        copyOut.write(magicBytes);
        final String magic = new String(magicBytes, StandardCharsets.US_ASCII);
        if (LOG.isDebugEnabled()) {
            LOG.debug("File signature\n" + magic);
        }

        // Check magic
        if (!MAGIC.equals(magic)) {
            throw new IOException("Missing AR magic");
        }

        // Digest of entries
        final DigestCalculatorProvider digestProvider = (digestAlgorithms == null || digestAlgorithms.length == 0) ? null : new BcDigestCalculatorProvider();

        // Read each header
        final ArrayList<Entry> entries = new ArrayList<>(5);
        final byte[] headerBytes = new byte[60];
        while (din.read(headerBytes, 0, 1) > 0) {

            // Read next file header (first byte is already read)
            din.readFully(headerBytes, 1, headerBytes.length - 1);
            copyOut.write(headerBytes);

            final ArFileHeader header = ArFileHeader.parse(headerBytes);

            // Read or skip the content
            final Map<AlgorithmIdentifier, byte[]> digests = new HashMap<>();
            final int fileSize = header.getFileSize();
            
            if (digestProvider == null) {
                final int skip = fileSize%2 == 0 ? fileSize : fileSize + 1; // Skip fileSize + padding if not even 2 byte boundary
                copyFully(din, copyOut, skip);
            } else {
                Collection<DigestCalculator> digestCalculators = createDigestCalculators(digestAlgorithms, digestProvider);
                ArrayList<OutputStream> outputs = new ArrayList<>(digestCalculators.stream().map((DigestCalculator c) -> c.getOutputStream()).collect(Collectors.<OutputStream>toList()));
                outputs.add(copyOut);
                OutputStream digestOut = new MultiOutputStream(outputs);
                
                // Copy/digest
                copyFully(in, digestOut, fileSize);
                
                digestCalculators.stream().forEach(c -> digests.put(c.getAlgorithmIdentifier(), c.getDigest()));
                
                // Skip if not 2 byte aligned
                if (fileSize%2 != 0) {
                    copyFully(in, copyOut, 1);
                }
            }

            entries.add(new Entry(header, digests));
        }

        return new ParsedArFile(entries);
    }
    
    private static Collection<DigestCalculator> createDigestCalculators(AlgorithmIdentifier[] digestAlgorithms, DigestCalculatorProvider provider) throws OperatorCreationException {
        final ArrayList<DigestCalculator> results = new ArrayList<>(digestAlgorithms.length);
        for (AlgorithmIdentifier algorithm : digestAlgorithms) {
            results.add(provider.get(algorithm));
        }
        return results;
    }
    
    private static void copyFully(InputStream in, OutputStream out, long length) throws IOException {
        long remaining = length;
        long n;
        while (0 < (n = IOUtils.copyLarge(in, out, 0, remaining))) {
            remaining -= n;
        }
        if (remaining != 0) {
            throw new EOFException("All " + length + " bytes not read. Remaining: " + remaining);
        }
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("ParsedArFile {\n");
        entries.forEach((e) -> {
            sb.append("   ").append(e).append("\n");
        });
        sb.append("}");
        return sb.toString();
    }

    public List<Entry> getEntries() {
        return entries;
    }

    public static class Entry {
        private final ArFileHeader header;
        private Map<AlgorithmIdentifier, byte[]> digests;

        public Entry(ArFileHeader header) {
            this.header = header;
        }

        private Entry(ArFileHeader header, Map<AlgorithmIdentifier, byte[]> digests) {
            this.header = header;
            this.digests = digests;
        }

        public ArFileHeader getHeader() {
            return header;
        }

        public Map<AlgorithmIdentifier, byte[]> getDigest() {
            return Collections.unmodifiableMap(digests);
        }

        @Override
        public String toString() {
            return "Entry{" + "header=" + header + ", digests=" + toString(digests) + '}';
        }

        private String toString(Map<AlgorithmIdentifier, byte[]> digests) {
            final StringBuilder sb = new StringBuilder();
            sb.append("{");
            digests.entrySet().forEach((entry) -> {
                sb.append(entry.getKey().getAlgorithm().getId()).append("=")
                        .append(Hex.toHexString(entry.getValue())).append(", ");
            });
            sb.append("}");
            return sb.toString();
        }
    }
}
