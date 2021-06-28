/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.onetime.caconnector;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.util.CertTools;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.IServices;
import org.signserver.server.SignServerContext;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.server.cryptotokens.ICryptoTokenV4;

/**
 * CAConnector simply generating a new self-signed certificate without
 * contacting an actual CA.
 *
 * @author Markus Kilås
 * @version $Id: SelfSignedCAConnector.java 9470 2018-08-07 09:59:52Z vinays $
 */
public class SelfSignedCAConnector implements ICAConnector {
    // Worker properties
    public static final String PROPERTY_CERTSIGNATUREALGORITHM = "CERTSIGNATUREALGORITHM";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private String certSignatureAlgorithm;

    @Override
    public void init(WorkerConfig config, SignServerContext context) {        

        // Required property CERTSIGNATUREALGORITHM
        certSignatureAlgorithm = config.getProperty(PROPERTY_CERTSIGNATUREALGORITHM, DEFAULT_NULL);
        if (certSignatureAlgorithm == null) {
            configErrors.add("Missing required property: " + PROPERTY_CERTSIGNATUREALGORITHM);
        }
    }

    @Override
    public List<String> getFatalErrors(ICryptoTokenV4 cryptoToken, IServices services) {
        return configErrors;
    }

    @Override
    public CAResponse requestCertificate(ICryptoTokenV4 backingToken, String name, PrivateKey privateKey, PublicKey publicKey, String provider, RequestContext context) throws CAException {
        if (!configErrors.isEmpty()) {
            throw new CAException(new IllegalStateException("Misconfigured"));
        }
        try {
            // Simulate a CA
            X509Certificate cert = CertTools.genSelfCert("CN=" + name, 1, null, privateKey, publicKey, certSignatureAlgorithm, false, provider);
            X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(cert.getEncoded());
            final List<X509CertificateHolder> certificateChain = Collections.<X509CertificateHolder>singletonList(x509CertificateHolder);
            return new CAResponse(x509CertificateHolder, certificateChain);
        } catch (OperatorCreationException | CertificateException | IOException ex) {
            throw new CAException(ex);
        }
    }
}
