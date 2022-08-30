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
package org.signserver.module.jarchive.impl.signapk;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.signserver.common.IllegalRequestException;

/**
 * Helper methods for operations on the JAR/APK/ZIP files.
 * Added so that the internal methods can be re-used by both client-
 * and server-side construction.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ApkHelper {
    
    public static final String CREATED_BY = SignApkSigner.CREATED_BY;
    
    /**
     * Copy files from in to out given the manifest file and the settings provided.
     * @param offset the start offset
     * @param manifest to read entries from
     * @param in to read from
     * @param out to write to
     * @param alignment to this number of bytes
     * @param keepSignatures if signatures should be kept
     * @param replaceSignature if the signature should be replaced
     * @param signatureName to use for the signature file name
     * @throws IOException in case of IO errors
     * @throws IllegalRequestException in case of incorrect settings
     */
    public static void copyFiles(long offset, Manifest manifest, JarFile in, JarOutputStream out, int alignment, boolean keepSignatures, boolean replaceSignature, String signatureName) throws IOException, IllegalRequestException {
        SignApk.copyFiles(offset, manifest, in, out, -1, alignment, keepSignatures, replaceSignature, signatureName);
    }
    
    /**
     * Adds hashes of every file to the manifest using the supplied algorithm names.
     * @param jar to read
     * @param digestAlgorithms to use
     * @param createdBy string to use
     * @return the new manifest
     * @throws IOException
     * @throws GeneralSecurityException 
     */
    public static Manifest addDigestsToManifest(JarFile jar, List<String> digestAlgorithms, String createdBy)
        throws IOException, GeneralSecurityException {
        return SignApk.addDigestsToManifest(jar, digestAlgorithms, createdBy);
    }
    
    /**
     * Create the signature file.
     *
     * @param manifest to read from
     * @param out to write the signature file to
     * @param digestAlgorithm to use
     * @param createdBy string to use
     * @throws IOException in case of IO errors
     * @throws GeneralSecurityException for errors hashing
     */
    public static void writeSignatureFile(Manifest manifest, OutputStream out,
                                           String digestAlgorithm, String createdBy) throws IOException, GeneralSecurityException {
        SignApk.writeSignatureFile(manifest, out, digestAlgorithm, createdBy);
    }
}
