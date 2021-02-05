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

import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.util.DataSources;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CertTools;

/**
 * Parser for ApkHashSigner pre-responses.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkPreResponseParser {
    public static final String SIGNER_CERTIFICATE_CHAIN = "SIGNER_CERTIFICATE_CHAIN";
    public static final String NUMBER_OF_OTHER_SIGNERS = "NUMBER_OF_OTHER_SIGNERS";
    public static final String OTHER_SIGNER_PREFIX = "OTHER_SIGNER_";
    public static final String NAME_SUFFIX = ".NAME";
    public static final String CERTIFICATE_CHAIN_SUFFIX = ".CERTIFICATE_CHAIN";
    public static final String LINEAGE_FILE_CONTENT = "LINEAGE_FILE_CONTENT";
    
    private final Properties properties;

    /**
     * Constructor for the ApkPreResponseParser.
     *
     * @param response Pre-response in the form of a byte array
     * @throws IOException 
     */
    public ApkPreResponseParser(final byte[] response) throws IOException {
        properties = new Properties();
        properties.load(new ByteArrayInputStream(response));
    }

    /**
     * Gets the signer certificate chain from the response.
     *
     * @return Certificate chain, or null if none where available in the response.
     * @throws CertificateParsingException 
     */
    public List<Certificate> getSignerCertificateChain() throws CertificateParsingException {
        final String signerCertificateChainValue =
                properties.getProperty(SIGNER_CERTIFICATE_CHAIN);

        if (signerCertificateChainValue != null) {
            return createCertificateChain(signerCertificateChainValue);
        } else {
            return null;
        }
    }

    /**
     * Gets the number of other signers specified in the response.
     *
     * @return Gets the number of other signers (0 if the field was not
     *         included in the response)
     */
    public int getNumberOfOtherSigners() {
        final String numberOfOtherSignersValue =
                properties.getProperty(NUMBER_OF_OTHER_SIGNERS);

        if (numberOfOtherSignersValue != null) {
            try {
                final int numberOfOtherSigners = Integer.parseInt(numberOfOtherSignersValue);

                if (numberOfOtherSigners < 0) {
                    throw new IllegalArgumentException("Number of other signers can not be negative");
                }

                return numberOfOtherSigners;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Illegal number of other signers: " +
                                                   numberOfOtherSignersValue);
            }
        } else {
            return 0;
        }
    }

    /**
     * Gets the name of other signer with a given index (0-based).
     *
     * @param index
     * @return Name of other signer, or null if no signer with the given index exists
     */
    public String getNameForOtherSigner(final int index) {
        final String property = OTHER_SIGNER_PREFIX + index + NAME_SUFFIX;
        final String nameValue = properties.getProperty(property);

        return nameValue;
    }

    /**
     * Get signer certificate chain for signer with given index.
     *
     * @param index
     * @return Signer certificate chain, or null if no signer with the given index exists
     * @throws CertificateParsingException 
     */
    public List<Certificate> getCertificateChainForOtherSigner(final int index)
            throws CertificateParsingException {
        final String property =
                OTHER_SIGNER_PREFIX + index + CERTIFICATE_CHAIN_SUFFIX;
        final String value = properties.getProperty(property);

        if (value != null) {
            return createCertificateChain(value);
        } else {
            return null;
        }
    }

    /**
     * Get signing certificate lineage content from the response.
     *
     * @return Signing certificate lineage, or null if no lineage was specified in the response
     * @throws IOException 
     */
    public SigningCertificateLineage getLineageFileContent() throws IOException {
        final String property = properties.getProperty(LINEAGE_FILE_CONTENT);

        if (property != null) {
            return SigningCertificateLineage.readFromDataSource(DataSources.asDataSource(ByteBuffer.wrap(Base64.decode(property))));
        } else {
            return null;
        }
    }
    
    private static List<Certificate> createCertificateChain(final String value)
            throws CertificateParsingException {
        final List<Certificate> result = new ArrayList<>();

        for (final String part : value.split(";")) {
            result.add(CertTools.getCertfromByteArray(Base64.decode(part.trim()),
                                                      Certificate.class));
        }

        return result;
    }
}
