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
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import javax.persistence.EntityManager;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.signserver.common.*;
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
            } catch (NumberFormatException ex) {
                configErrors.add("Unable to parse property " + WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + ". Only numbers >= 0 supported: " + ex.getLocalizedMessage());
            }
        }
    }

    /**
     * @see org.signserver.server.IProcessable#getStatus()
     */
    @Override
    public WorkerStatusInfo getStatus(final List<String> additionalFatalErrors, final IServices services) {
        WorkerStatusInfo info;
        final List<String> fatalErrors = new LinkedList<>(additionalFatalErrors);
        fatalErrors.addAll(getFatalErrors(services));

        final boolean keyUsageCounterDisabled = config.getProperty(SignServerConstants.DISABLEKEYUSAGECOUNTER, "FALSE").equalsIgnoreCase("TRUE");

        ICryptoTokenV4 token = null;
        try {
            token = getCryptoToken(services);
        } catch (SignServerException ex) {
            // getFatalErrors will pick up crypto token errors gathered
            // during creation of the crypto token
        }

        List<WorkerStatusInfo.Entry> briefEntries = new LinkedList<>();
        List<WorkerStatusInfo.Entry> completeEntries = new LinkedList<>();

        long keyUsageCounterValue = 0;
        int status = WorkerStatus.STATUS_OFFLINE;
        X509Certificate signerCertificate = null;

        if (token != null) {
            status = token.getCryptoTokenStatus(services);
        }
        
        if (!isNoCertificates()) {
            RequestContext context = new RequestContext(true);
            context.setServices(services);
            ICryptoInstance crypto = null;
            try {
                crypto = acquireDefaultCryptoInstance(context);

                signerCertificate =
                        (X509Certificate) getSigningCertificate(crypto);
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

            } catch (CryptoTokenOfflineException e) {} // the error will have been picked up by getCryptoTokenFatalErrors already

            catch (NumberFormatException ex) {
                fatalErrors.add("Incorrect value in worker property " + SignServerConstants.KEYUSAGELIMIT + ": " + ex.getMessage());
            } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | SignServerException ex) {
                fatalErrors.add("Unable to obtain certificate from token: " + ex.getLocalizedMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to obtain certificate from token", ex);
                }
            } finally {
                if (crypto != null) {
                    try {
                        releaseCryptoInstance(crypto, context);
                    } catch (SignServerException ex) {
                        LOG.warn("Unable to release crypto instance", ex);
                    }
                }
            }
        }

        if (status == WorkerStatus.STATUS_OFFLINE) {
            fatalErrors.add("Error Crypto Token is disconnected");
        }

        // Worker status
        briefEntries.add(new WorkerStatusInfo.Entry("Worker status", status == WorkerStatus.STATUS_ACTIVE && (fatalErrors.isEmpty()) ? "Active" : "Offline"));
        briefEntries.add(new WorkerStatusInfo.Entry("Token status", status == WorkerStatus.STATUS_ACTIVE ? "Active" : "Offline"));

        // Signings
        if (!isNoCertificates()) {
            String signingsValue = String.valueOf(keyUsageCounterValue);
            long keyUsageLimit = -1;
            try {
                keyUsageLimit = Long.valueOf(config.getProperty(SignServerConstants.KEYUSAGELIMIT));
            } catch(NumberFormatException ignored) {}
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
            configValue.append(key).append("=").append(properties.getProperty(key)).append("\n\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Worker properties", configValue.toString()));

        // Clients
        final StringBuilder clientsValue = new StringBuilder();
        for (AuthorizedClient client : config.getAuthorizedClients()) {
            clientsValue.append(client.getCertSN()).append(", ").append(client.getIssuerDN()).append("\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Authorized clients (serial number, issuer DN)", clientsValue.toString()));

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
        } catch (SignServerException ignored) {} // NOPMD errors are added to cryptoTokenFatalErrors
        errors.addAll(getCryptoTokenFatalErrors(services));
        if (!isNoCertificates()) {
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
            crypto = acquireDefaultCryptoInstance(context);
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
                } else if (Arrays.equals(certificate.getPublicKey().getEncoded(),
                        publicKeyInToken.getEncoded())) {
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
        } catch (SignServerException e) {
            result.add("Could not get crypto token");
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signer " + workerId + ": Could not get crypto token: " + e.getMessage());
            }
        } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException ex) {
            result.add("Could not get crypto token");
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signer " + workerId + ": Could not get crypto token: " + ex.getMessage());
            }
        } finally {
            if (crypto != null) {
                try {
                    releaseCryptoInstance(crypto, context);
                } catch (SignServerException ex) {
                    LOG.warn("Unable to release crypto instance", ex);
                }
            }
        }

        // Check signer validity
        if (certificate instanceof X509Certificate) {
            try {
                ValidityTimeUtils.checkSignerValidity(new WorkerIdentifier(workerId), getConfig(), (X509Certificate) certificate);
            } catch (CryptoTokenOfflineException ex) {
                result.add(ex.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": Signer certificate validity time check failed: " + ex.getMessage());
                }
            } // Invalid value for minRemainingCertValidity parameter gives NumberFormatException 
            catch (NumberFormatException ex) {
                result.add(ex.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": Signer certificate validity time check failed: " + ex.getMessage());
                }
            }
        }

        if (!hasSetIncludeCertificateLevels || includeCertificateLevels > 0) {
            // Check that certificiate chain contains the signer certificate
            try {
                getCertStoreWithChain(certificate, certificateChain);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | CertStoreException | IOException | CertificateEncodingException | InvalidAlgorithmParameterException ex) {
                result.add("Unable to get certificate chain");
                LOG.error("Signer " + workerId + ": Unable to get certificate chain: " + ex.getMessage());
            } catch (CryptoTokenOfflineException ex) {
                result.add(ex.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": Could not get signer certificate in chain: " + ex.getMessage());
                }
            }
        }

        return result;
    }

    protected Store getCertStoreWithChain(Certificate signingCert, List<Certificate> signingCertificateChain) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CryptoTokenOfflineException, CertStoreException, CertificateEncodingException, IOException {
        if (signingCertificateChain == null) {
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
