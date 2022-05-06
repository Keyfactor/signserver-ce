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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import javax.persistence.EntityManager;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.signserver.common.*;
import static org.signserver.common.SignServerConstants.DISABLED;
import org.signserver.server.BaseProcessable;
import org.signserver.server.IServices;
import org.signserver.server.KeyUsageCounterHash;
import org.signserver.server.ValidityTimeUtils;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
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
   
    protected int includeCertificateLevels;
    protected boolean hasSetIncludeCertificateLevels;
    
    private List<String> configErrors = new LinkedList<>();

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss z");
    
    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        final String includeCertificateLevelsProperty = config.getProperties().getProperty(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS);

        if (includeCertificateLevelsProperty != null) {
            hasSetIncludeCertificateLevels = true;
            
            try {
                includeCertificateLevels = Integer.parseInt(includeCertificateLevelsProperty);
                if (includeCertificateLevels < 0) {
                    configErrors.add("Illegal value for property " + WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + ". Only numbers >= 0 supported.");
                }
            } catch (NumberFormatException e) {
                configErrors.add("Unable to parse property " + WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + ". Only numbers >= 0 supported: " + e.getLocalizedMessage());
                includeCertificateLevels = -1;
            }
        }
    }

    /**
     * @see org.signserver.server.IProcessable#getStatus()
     */
    @Override
    public WorkerStatusInfo getStatus(final List<String> additionalFatalErrors, final IServices services) {
        final List<String> fatalErrors = new LinkedList<>(additionalFatalErrors);
        fatalErrors.addAll(getFatalErrors(services));

        final boolean keyUsageCounterDisabled = config.getProperty(SignServerConstants.DISABLEKEYUSAGECOUNTER, "FALSE").equalsIgnoreCase("TRUE");

        List<WorkerStatusInfo.Entry> briefEntries = new LinkedList<>();
        List<WorkerStatusInfo.Entry> completeEntries = new LinkedList<>();

        long keyUsageCounterValue = 0;
        int status = isCryptoTokenActive(services) ? WorkerStatus.STATUS_ACTIVE : WorkerStatus.STATUS_OFFLINE;
        X509Certificate signerCertificate = null;

        if (!isNoCertificates()) {
            RequestContext context = new RequestContext(true);
            context.setServices(services);
            ICryptoInstance crypto = null;
            try {
                crypto = acquireDefaultCryptoInstance(Collections.<String, Object>emptyMap(), context);

                signerCertificate = (X509Certificate) getSigningCertificate(crypto);
                if (signerCertificate != null) {
                    final long keyUsageLimit = Long.valueOf(config.getProperty(SignServerConstants.KEYUSAGELIMIT, "-1"));

                    KeyUsageCounter counter = getSignServerContext().getKeyUsageCounterDataService().getCounter(KeyUsageCounterHash.create(signerCertificate.getPublicKey()));
                    if ((counter == null && !keyUsageCounterDisabled) 
                            || (keyUsageLimit != -1 && status == WorkerStatus.STATUS_ACTIVE && (counter == null || counter.getCounter() >= keyUsageLimit))) {
                        fatalErrors.add("Key usage limit exceeded or not initialized");
                    }

                    if (counter != null) {
                        keyUsageCounterValue = counter.getCounter();
                    }
                }
            } catch (CryptoTokenOfflineException e) {
                // The error will have been picked up by getCryptoTokenFatalErrors already
            } catch (NumberFormatException e) {
                fatalErrors.add("Incorrect value in worker property " + SignServerConstants.KEYUSAGELIMIT + ": " + e.getMessage());
            } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | SignServerException e) {
                fatalErrors.add("Unable to obtain certificate from token: " + e.getLocalizedMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to obtain certificate from token", e);
                }
            } finally {
                if (crypto != null) {
                    try {
                        releaseCryptoInstance(crypto, context);
                    } catch (SignServerException e) {
                        LOG.warn("Unable to release crypto instance", e);
                    }
                }
            }
        }

        if (status == WorkerStatus.STATUS_OFFLINE) {
            fatalErrors.add("Crypto Token is disconnected");
        }

        // Worker status
        boolean workerSetAsDisabled = config.getProperty(DISABLED, "FALSE").equalsIgnoreCase("TRUE");
        if (workerSetAsDisabled) {
            briefEntries.add(new WorkerStatusInfo.Entry("Worker status", "Disabled"));
        } else {
            briefEntries.add(new WorkerStatusInfo.Entry("Worker status", status == WorkerStatus.STATUS_ACTIVE && (fatalErrors.isEmpty()) ? "Active" : "Offline"));
        }

        // Token status
        briefEntries.add(new WorkerStatusInfo.Entry("Token status", status == WorkerStatus.STATUS_ACTIVE ? "Active" : "Offline"));

        // Signings
        if (!isNoCertificates()) {
            String signingsValue = String.valueOf(keyUsageCounterValue);
            long keyUsageLimit = -1;
            try {
                keyUsageLimit = Long.valueOf(config.getProperty(SignServerConstants.KEYUSAGELIMIT));
            } catch(NumberFormatException e) {
                // Ignored
            }
            if (keyUsageLimit >= 0) {
                signingsValue += " of " + keyUsageLimit;
            }
            if (keyUsageCounterDisabled) {
                signingsValue += " (counter disabled)";
            }
            briefEntries.add(new WorkerStatusInfo.Entry("Signings", signingsValue));
        }

        // Disabled
        if ("TRUE".equalsIgnoreCase(config.getProperty(SignServerConstants.DISABLED))) {
            briefEntries.add(new WorkerStatusInfo.Entry("", "Signer is disabled"));
        }

        // Properties
        final StringBuilder configValue = new StringBuilder();
        Properties properties = config.getProperties();
        for (String key : properties.stringPropertyNames()) {
            final String value = config.shouldMaskProperty(key) ?
                                 WorkerConfig.WORKER_PROPERTY_MASK_PLACEHOLDER :
                                 properties.getProperty(key);
            configValue.append(key).append("=").append(value).append("\n\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Worker properties", configValue.toString()));

        // Clients
        final StringBuilder clientsValue = new StringBuilder();
        config.getAuthorizedClientsGen2().forEach((client) -> {
            clientsValue.append(client.getMatchSubjectWithType()).append(": ").append(client.getMatchSubjectWithValue()).append(" | ")
                    .append(client.getMatchIssuerWithType()).append(": ").append(client.getMatchIssuerWithValue())
                    .append(StringUtils.isBlank(client.getDescription()) ? "" : " | Description: " + client.getDescription()).append("\n");
        });
        completeEntries.add(new WorkerStatusInfo.Entry("Authorized clients", clientsValue.toString()));

        // Certificate
        if (!isNoCertificates()) {
            final String certificateValue;
            if (signerCertificate == null) {
                certificateValue = "Error: No Signer Certificate have been uploaded to this signer.\n";
            } else {
                final StringBuilder buff = new StringBuilder();
                buff.append("Subject DN:     ").append(signerCertificate.getSubjectDN().toString()).append("\n");
                buff.append("Serial number:  ").append(signerCertificate.getSerialNumber().toString(16)).append("\n");
                buff.append("Issuer DN:      ").append(signerCertificate.getIssuerDN().toString()).append("\n");
                buff.append("Valid from:     ").append(FDF.format(signerCertificate.getNotBefore())).append("\n");
                buff.append("Valid until:    ").append(FDF.format(signerCertificate.getNotAfter())).append("\n");
                certificateValue = buff.toString();
            }
            completeEntries.add(new WorkerStatusInfo.Entry("Signer certificate", certificateValue));
        }

        return new WorkerStatusInfo(workerId, config.getProperty("NAME"),
                                    "Signer", status, briefEntries, fatalErrors,
                                    completeEntries, config);
    }

    @Override
    protected List<String> getFatalErrors(IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));

        // Load crypto token so its errors are checked
        try {
            getCryptoToken(services);
        } catch (SignServerException e) {
            // NOPMD errors are added to cryptoTokenFatalErrors
        }
        errors.addAll(getCryptoTokenFatalErrors(services));
        if (!isNoCertificates() && isCryptoTokenActive(services)) {
            // Get certificate errors if worker is configured for certificates and Crypto Token is active
            errors.addAll(getSignerCertificateFatalErrors(services));
        }
        errors.addAll(configErrors);
        return errors;
    }

    /**
     * Checks that the signer certificate is available and that it matches the 
     * key-pair in the crypto token and that the time is within the signer's 
     * validity.
     * The errors returned from this method is included in the list of errors
     * returned from getFatalErrors().
     * Signer implementation can override this method and just return an empty 
     * list if they don't require a signer certificate to be present.
     *
     * @param services Services for implementations to use
     * @return List of errors or an empty list in case of no errors
     */
    protected List<String> getSignerCertificateFatalErrors(IServices services) {
        final LinkedList<String> result = new LinkedList<>(super.getFatalErrors(services));
        // Check if certificate matches key
        RequestContext context = new RequestContext(true);
        context.setServices(services);
        ICryptoInstance crypto = null;
        Certificate certificate = null;
        List<Certificate> certificateChain = null;
        try {
            crypto = acquireDefaultCryptoInstance(Collections.<String, Object>emptyMap(), context);
            certificate = getSigningCertificate(crypto);
            certificateChain = getSigningCertificateChain(crypto);
            final ICryptoTokenV4 token = getCryptoToken(services);
            if (token == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": No crypto token");
                }
                result.add("No crypto token available");
            } else if (certificate == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": No certificate");
                }
                result.add("No signer certificate available");
            } else {
                final PublicKey publicKeyInToken = crypto.getPublicKey();
                if (publicKeyInToken == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Signer " + workerId + ": Key not configured or not available");
                    }
                    result.add("Key not configured or not available");
                } else if (publicKeyEquals(publicKeyInToken, certificate.getPublicKey())) {
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
        } catch (CryptoTokenOfflineException e) {
            result.add(e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signer " + workerId + ": Could not get signer certificate: " + e.getMessage());
            }
        } catch (SignServerException | InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException e) {
            result.add("Could not get crypto token");
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signer " + workerId + ": Could not get crypto token: " + e.getMessage());
            }
        } finally {
            if (crypto != null) {
                try {
                    releaseCryptoInstance(crypto, context);
                } catch (SignServerException e) {
                    LOG.warn("Unable to release crypto instance", e);
                }
            }
        }

        // Check signer validity
        if (certificate instanceof X509Certificate) {
            try {
                ValidityTimeUtils.checkSignerValidity(new WorkerIdentifier(workerId), getConfig(), (X509Certificate) certificate);
            } catch (CryptoTokenOfflineException | NumberFormatException e) {
                // Invalid value for minRemainingCertValidity parameter gives NumberFormatException 
                result.add(e.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": Signer certificate validity time check failed: " + e.getMessage());
                }
            }
        }

        if (!hasSetIncludeCertificateLevels || includeCertificateLevels > 0) {
            // Check that certificiate chain contains the signer certificate
            try {
                getCertStoreWithChain(certificate, certificateChain);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | CertStoreException | IOException | CertificateEncodingException | InvalidAlgorithmParameterException e) {
                result.add("Unable to get certificate chain");
                LOG.error("Signer " + workerId + ": Unable to get certificate chain: " + e.getMessage());
            } catch (CryptoTokenOfflineException e) {
                result.add(e.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": Could not get signer certificate in chain: " + e.getMessage());
                }
            }
        }

        return result;
    }
    
    protected Store getCertStoreWithChain(Certificate signingCert, List<Certificate> signingCertificateChain) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CryptoTokenOfflineException, CertStoreException, CertificateEncodingException, IOException {
        if (signingCertificateChain == null || signingCertificateChain.isEmpty()) {
            throw new CryptoTokenOfflineException("Certificate chain not available");
        } else {
            JcaCertStore certStore =
                    new JcaCertStore(includedCertificates(signingCertificateChain));

            if (!containsCertificate(certStore, signingCert) &&
                (!hasSetIncludeCertificateLevels || includeCertificateLevels > 0)) {
                throw new CryptoTokenOfflineException("Signer certificate not included in certificate chain");
            }
            return certStore;
        }
    }

    /**
     * Checks if the Crypto Token is active.
     * 
     * @param services services for implementations to use
     * @return true if the Crypto Token is active
     */
    protected boolean isCryptoTokenActive(IServices services) {
        int status = WorkerStatus.STATUS_OFFLINE;
        try {
            ICryptoTokenV4 token = getCryptoToken(services);
            if (token != null) {
                status = token.getCryptoTokenStatus(services);
            }
        } catch (SignServerException e) {
            // Let status be offline
        }
        return status == WorkerStatus.STATUS_ACTIVE;
    }

    /**
     * @return True if the CertStore contained the Certificate
     */
    private boolean containsCertificate(final Store store, final Certificate subject) throws CertStoreException, IOException, CertificateEncodingException {
        final X509CertificateHolder cert = new X509CertificateHolder(subject.getEncoded());
        final Collection<?> matchedCerts = store.getMatches(new Selector() {
            
            @Override
            public boolean match(Object obj) {
                return cert.equals(obj);
            }
            
            @Override
            public Object clone() {
                return this;
            }
        });
        return matchedCerts.size() > 0;
    }

    /**
     * Given a list of certificates, return a list of at most the number given by INCLUDE_CERTIFICATE_LEVELS
     * from the beginning. If the list is shorter than the property specifies, return the entire list.
     * 
     * @param certs List of certificates
     * @return List of at most the desired certificate levels to include.
     */
    protected List<Certificate> includedCertificates(final List<Certificate> certs) {
        if (hasSetIncludeCertificateLevels) {
            return certs.subList(0, Math.min(includeCertificateLevels, certs.size()));
        } else {
            return certs;
        }
    }

}
