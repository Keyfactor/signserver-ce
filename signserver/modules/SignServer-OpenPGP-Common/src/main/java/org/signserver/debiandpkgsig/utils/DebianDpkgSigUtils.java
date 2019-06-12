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
package org.signserver.debiandpkgsig.utils;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.debiandpkgsig.ar.ArFileHeader;
import org.signserver.debiandpkgsig.ar.ParsedArFile;

/**
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class DebianDpkgSigUtils {
    /**
     * Create a dpkg-sig manifest.
     * 
     * Sample:
     * <code>
     * Version: 4\n
     * Signer: 123456789ABCDE\n
     * Date: Wed May 15 08:51:48 2019\n
     * Role: builder\n
     * Files: \n
     *  3cf918272ffa5de195752d73f3da3e5e 7959c969e092f2a5a8604e2287807ac5b1b384ad 4 debian-binary\n
     *  94ff0dae369a24df829ff58c2606f8e6 5532b60c23ec7acee08a36d0803dc3d96bf0f1a0 336 control.tar.xz\n
     *  35ddaef8a5af0ae5bf7743f519b834c5 81eb7974a37b6b810eccf1cfe4df3994587cd7bb 256 data.tar.xz\n
     * </code>
     * 
     * @param fingerprint Fingerprint of the public GPG key
     * @param date Date of signature creation
     * @param arFile Parsed AR file
     * @return A string representation of the manifest to be signed
     */
    public static String createManifest(final byte[] fingerprint,
                                        final Date date,
                                        final ParsedArFile arFile) {
        final StringBuilder sb = new StringBuilder();
        final DateFormat format = new SimpleDateFormat("E MMM d HH:mm:ss yyyy", Locale.ENGLISH);
        
//        if date format should be displayed in UTC, uncomment below
//        TimeZone timeZone = TimeZone.getTimeZone("UTC");
//        format.setTimeZone(timeZone);

        sb.append("Version: 4\n");
        sb.append("Signer: ").append(Hex.toHexString(fingerprint).toUpperCase(Locale.ENGLISH)).append("\n");
        sb.append("Date: ").append(format.format(date)).append("\n");
        sb.append("Role: builder\n");
        sb.append("Files: ");

        for (final ParsedArFile.Entry entry : arFile.getEntries()) {
            final ArFileHeader header = entry.getHeader();
            final byte[] md5Digest =
                    entry.getDigest().get(new AlgorithmIdentifier(CMSAlgorithm.MD5));
            final byte[] sha1Digest =
                    entry.getDigest().get(new AlgorithmIdentifier(CMSAlgorithm.SHA1));
            
            if (md5Digest == null) {
                throw new IllegalArgumentException("Missing MD5 digest for: " +
                                                   header.getFileIdentifier());
            }

            if (sha1Digest == null) {
                throw new IllegalArgumentException("Missing SHA-1 digest for: " +
                                                   header.getFileIdentifier());
            }

            sb.append("\n ");
            sb.append(Hex.toHexString(md5Digest).toLowerCase(Locale.ENGLISH));
            sb.append(" ");
            sb.append(Hex.toHexString(sha1Digest).toLowerCase(Locale.ENGLISH));
            sb.append(" ");
            sb.append(header.getFileSize());
            sb.append(" ");
            sb.append(header.getFileIdentifier());
        }
        
        return sb.toString();
    }
}
