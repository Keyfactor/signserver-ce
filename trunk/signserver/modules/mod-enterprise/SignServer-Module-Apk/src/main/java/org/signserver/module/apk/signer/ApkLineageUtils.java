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
package org.signserver.module.apk.signer;

import com.android.apksig.ApkVerifier;
import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.internal.util.ByteBufferDataSource;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.apache.log4j.Logger;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.data.ReadableData;
import org.signserver.server.cryptotokens.ICryptoInstance;

/**
 * Utility methods for APK lineages.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkLineageUtils {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(ApkLineageUtils.class);

    /**
     * Gets a SigningCertificateLineage from a request, either taken from
     * an APK file, or a stand-alone lineage file, depending on the content
     * provided.
     * 
     * @param requestData Request to read data from
     * @return A SigningCertificateLinage, if successfully read and parsed.
     * @throws NoSuchAlgorithmException
     * @throws IllegalRequestException
     * @throws SignServerException 
     */
    public static SigningCertificateLineage getLineageFromRequest(final ReadableData requestData) throws NoSuchAlgorithmException, IllegalRequestException, SignServerException {
        SigningCertificateLineage lineage;

        try {
            final ApkVerifier.Builder apkVerifierBuilder =
                new ApkVerifier.Builder(requestData.getAsFile());

            ApkVerifier verifier = apkVerifierBuilder.build();
            ApkVerifier.Result verify = verifier.verify();

            lineage = verify.getSigningCertificateLineage();

            if (lineage == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No lineage found in APK");
                }
                throw new IllegalRequestException("No lineage found in APK");
            }
        } catch (ApkFormatException e) {
            // the file is not an APK, try parsing it as a lineage file
            try {
                final ByteBuffer buffer = ByteBuffer.wrap(requestData.getAsByteArray());
                final ByteBufferDataSource dataSource =
                    new ByteBufferDataSource(buffer);
                lineage = SigningCertificateLineage.readFromDataSource(dataSource);
            } catch (IOException ex) {
                throw new IllegalRequestException("Invalid lineage file", ex);
            }
        } catch (IOException e) {
            throw new IllegalRequestException("Invalid APK file", e);
        } catch (IllegalStateException e) {
            throw new SignServerException("Illegal state", e);
        }
        
        return lineage;
    }

    /**
     * Gets a SignerConfig corresponding to a crypto instance.
     * 
     * @param cryptoInstance
     * @return SignerConfig instance
     */
    public static SigningCertificateLineage.SignerConfig getSignerConfigForCryptoInstance(final ICryptoInstance cryptoInstance) {
        final X509Certificate cert =
                (X509Certificate) cryptoInstance.getCertificate();
        final PrivateKey privKey = cryptoInstance.getPrivateKey();

        return new SigningCertificateLineage.SignerConfig.Builder(privKey, cert).build();
    }
}
