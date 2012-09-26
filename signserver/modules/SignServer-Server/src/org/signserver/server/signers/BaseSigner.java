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
package org.signserver.server.signers;

import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.server.BaseProcessable;
import org.signserver.server.KeyUsageCounterHash;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.entities.KeyUsageCounter;

/**
 * Base class that all signers can extend to cover basic in common
 * functionality.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public abstract class BaseSigner extends BaseProcessable implements ISigner {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(BaseSigner.class);

    /**
     * @see org.signserver.server.IProcessable#getStatus()
     */
    @Override
    public WorkerStatus getStatus() {
        SignerStatus retval;
        final List<String> fatalErrors = new LinkedList<String>(getFatalErrors());

        final boolean keyUsageCounterDisabled = config.getProperty(SignServerConstants.DISABLEKEYUSAGECOUNTER, "FALSE").equalsIgnoreCase("TRUE");
        
        try {
            final Certificate cert = getSigningCertificate();
            final long keyUsageLimit = Long.valueOf(config.getProperty(SignServerConstants.KEYUSAGELIMIT, "-1"));

            if (cert != null) { 
                KeyUsageCounter counter = getSignServerContext().getKeyUsageCounterDataService().getCounter(KeyUsageCounterHash.create(cert.getPublicKey()));
                int status = getCryptoToken().getCryptoTokenStatus();
                if ((counter == null && !keyUsageCounterDisabled) 
                        || (keyUsageLimit != -1 && status == CryptoTokenStatus.STATUS_ACTIVE && (counter == null || counter.getCounter() >= keyUsageLimit))) {
                    fatalErrors.add("Key usage limit exceeded or not initialized");
                }

                if (counter != null) {
                    retval = new SignerStatus(workerId, status, fatalErrors, new ProcessableConfig(config), cert, counter.getCounter());
                } else {
                    retval = new SignerStatus(workerId, status, fatalErrors, new ProcessableConfig(config), cert);
                }
            } else {
                retval = new SignerStatus(workerId, getCryptoToken().getCryptoTokenStatus(), fatalErrors, new ProcessableConfig(config), cert);
            }
        } catch (CryptoTokenOfflineException e) {
            retval = new SignerStatus(workerId, getCryptoToken().getCryptoTokenStatus(), fatalErrors, new ProcessableConfig(config), null);
        } catch (NumberFormatException ex) {
            fatalErrors.add("Incorrect value in worker property " + SignServerConstants.KEYUSAGELIMIT + ": " + ex.getMessage());
            retval = new SignerStatus(workerId, getCryptoToken().getCryptoTokenStatus(), fatalErrors, new ProcessableConfig(config), null);
        }
        retval.setKeyUsageCounterDisabled(keyUsageCounterDisabled);
        return retval;
    }

    @Override
    protected List<String> getFatalErrors() {
        final LinkedList<String> errors = new LinkedList<String>(super.getFatalErrors());
        errors.addAll(getSignerCertificateFatalErrors());
        return errors;
    }

    /**
     * Checks that the signer certificate is available and that it matches the 
     * key-pair in the crypto token.
     * The errors returned from this method is included in the list of errors
     * returned from getFatalErrors().
     * Signer implementation can override this method and just return an empty 
     * list if they don't require a signer certificate to be present.
     *
     * @return List of errors or an empty list in case of no errors
     */
    protected List<String> getSignerCertificateFatalErrors() {
        final LinkedList<String> result = new LinkedList<String>(super.getFatalErrors());
        // Check if certificate matches key
        try {
            Certificate certificate = getSigningCertificate();
            if (certificate == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": No certificate");
                }
                result.add("No signer certificate available");
            } else {
                if (Arrays.equals(certificate.getPublicKey().getEncoded(),
                        getCryptoToken().getPublicKey(
                        ICryptoToken.PURPOSE_SIGN).getEncoded())) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Signer " + workerId + ": Certificate matches key");
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Signer " + workerId + ": Certificate does not match key");
                    }
                    result.add("Certificate does not match key");
                }
            }
        } catch (CryptoTokenOfflineException ex) {
            result.add("No signer certificate available");
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signer " + workerId + ": Could not get signer certificate: " + ex.getMessage());
            }
        }
        return result;
    }    
}