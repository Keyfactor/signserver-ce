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
package org.signserver.peers.ejb.keybind;

import java.io.ByteArrayInputStream;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.ui.DynamicUiProperty;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignServerConstants;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.ejbca.peerconnector.common.PeersWorkerProperties;
import org.signserver.module.renewal.worker.RenewalWorker;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.server.log.AdminInfo;

/**
 * SignServer implementation of what is needed for the InternalKeyBindingMgtmSession to work with peers.
 *
 * @version $Id$
 */
@Stateless
public class InternalKeyBindingMgmtSessionBean implements SignServerInternalKeyBindingMgmtSessionLocal, InternalKeyBindingMgmtSessionLocal {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(InternalKeyBindingMgmtSessionBean.class);

    @EJB
    private WorkerSessionLocal workerSession;
    
    @Override
    public List<InternalKeyBindingInfo> getAllInternalKeyBindingInfos(String internalKeyBindingType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public InternalKeyBindingInfo getInternalKeyBindingInfoNoLog(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public InternalKeyBinding getInternalKeyBindingReference(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<Collection<X509Certificate>> getListOfTrustedCertificates(InternalKeyBinding internalKeyBinding) throws CADoesntExistsException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Map<String, Map<String, DynamicUiProperty<? extends Serializable>>> getAvailableTypesAndProperties() { 
        return InternalKeyBindingFactory.INSTANCE.getAvailableTypesAndProperties();
    }

    @Override
    public List<Integer> getInternalKeyBindingIds(String internalKeyBindingType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<Integer> getInternalKeyBindingIds(AuthenticationToken authenticationToken, String internalKeyBindingType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public InternalKeyBinding getInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Integer getIdFromName(String internalKeyBindingName) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int createInternalKeyBinding(AuthenticationToken authenticationToken, String type, int id, String name, InternalKeyBindingStatus status, String certificateId, int cryptoTokenId, String keyPairAlias, boolean allowMissingKeyPair, String signatureAlgorithm, Map<String, Serializable> dataMap, List<InternalKeyBindingTrustEntry> trustedCertificateReferences) throws AuthorizationDeniedException, CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int createInternalKeyBinding(AuthenticationToken authenticationToken, String type, int id, String name, InternalKeyBindingStatus status, String certificateId, int cryptoTokenId, String keyPairAlias, String signatureAlgorithm, Map<String, Serializable> dataMap, List<InternalKeyBindingTrustEntry> trustedCertificateReferences) throws AuthorizationDeniedException, CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int createInternalKeyBinding(AuthenticationToken authenticationToken, String type, String name, InternalKeyBindingStatus status, String certificateId, int cryptoTokenId, String keyPairAlias, String signatureAlgorithm, Map<String, Serializable> dataMap, List<InternalKeyBindingTrustEntry> trustedCertificateReferences) throws AuthorizationDeniedException, CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int persistInternalKeyBinding(AuthenticationToken authenticationToken, InternalKeyBinding internalKeyBinding) throws AuthorizationDeniedException, InternalKeyBindingNameInUseException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean deleteInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] getNextPublicKeyForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] generateCsrForNextKey(AuthenticationToken authenticationToken, int internalKeyBindingId, byte[] name) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        final AdminInfo admin = new AdminInfo(((X509CertificateAuthenticationToken) authenticationToken).getCertificate());
        try {
            final WorkerConfig config = workerSession.getCurrentWorkerConfig(internalKeyBindingId);
            String keyAlias = config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY);
            if (keyAlias == null) {
                keyAlias = config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
            }
            String signatureAlgorithm = config.getProperty(RenewalWorker.PROPERTY_SIGNATUREALGORITHM, "");
            if (signatureAlgorithm.trim().isEmpty()) {
                signatureAlgorithm = "SHA256withRSA";
            }
            String requestDN = config.getProperty(RenewalWorker.PROPERTY_REQUESTDN, "");
            if (requestDN.trim().isEmpty()) {
                requestDN = "CN=" + keyAlias;
            }
            final Base64SignerCertReqData csr = (Base64SignerCertReqData) workerSession.getCertificateRequest(admin, new WorkerIdentifier(internalKeyBindingId), new PKCS10CertReqInfo(signatureAlgorithm, requestDN, null), false, keyAlias);
            return Base64.decode(csr.getBase64CertReq());
        } catch (org.signserver.common.CryptoTokenOfflineException | InvalidWorkerIdException ex) {
            throw new CryptoTokenOfflineException(ex);
        }        
    }

    @Override
    public String updateCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException, CertificateImportException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void importCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId, byte[] certificate) throws AuthorizationDeniedException, CertificateImportException {
       throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public void importCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId, byte[] certificate, int type) throws AuthorizationDeniedException, CertificateImportException {
        final AdminInfo admin = new AdminInfo(((X509CertificateAuthenticationToken) authenticationToken).getCertificate());
        try {
            final byte[] signerCertificate;
            final List<byte[]> certificateChainBytes;
            final List<Certificate> certificateChain;
            
            final WorkerConfig config = workerSession.getCurrentWorkerConfig(internalKeyBindingId);

            switch (type) {
                case 0:
                    signerCertificate = certificate;
                    Certificate cert = CertTools.getCertfromByteArray(certificate, Certificate.class);
                    certificateChainBytes = new ArrayList<>();
                    if (config.getProperty(PeersWorkerProperties.PEERS_KEEPCHAIN, "").equalsIgnoreCase(Boolean.TRUE.toString())) {
                        // Get the old chain and only replace the signer certificate
                        certificateChain = workerSession.getSignerCertificateChain(new WorkerIdentifier(internalKeyBindingId));
                        if (certificateChain.isEmpty()) {
                            certificateChain.add(cert);
                        } else {
                            certificateChain.set(0, cert);
                        }
                        for (Certificate c : certificateChain) {
                            certificateChainBytes.add(c.getEncoded());
                        }
                    } else {
                        certificateChainBytes.add(certificate);
                        certificateChain = Arrays.asList(cert);
                    }
                    break;
                case 1:
                    certificateChain = CertTools.getCertsFromPEM(new ByteArrayInputStream(certificate), Certificate.class);
                    signerCertificate = certificateChain.get(0).getEncoded();
                    certificateChainBytes = new ArrayList<>(certificateChain.size());
                    for (Certificate c : certificateChain) {
                        certificateChainBytes.add(c.getEncoded());
                    }
                    break;
                default:
                    throw new CertificateImportException("Unsupported certificate encoding type: " + type);
            }

            final String nextKey = config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY);
            final String key;
            if (nextKey == null) {
                key = config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
            } else {
                key = nextKey;
            }
            
            // Verify that this is an accepted type of certificate to import for the current implementation
            checkCertificateIsOkToImport(internalKeyBindingId, certificateChain);

            if (nextKey != null) {
                workerSession.setWorkerProperty(admin, internalKeyBindingId, CryptoTokenHelper.PROPERTY_DEFAULTKEY, nextKey);
                workerSession.removeWorkerProperty(admin, internalKeyBindingId, CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY);
            }
            workerSession.uploadSignerCertificate(admin, internalKeyBindingId, signerCertificate, GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(admin, internalKeyBindingId, certificateChainBytes, GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.setWorkerProperty(admin, internalKeyBindingId, PeersWorkerProperties.PEERS_ISSUED, "true");
            workerSession.reloadConfiguration(admin, internalKeyBindingId);
        } catch (CertificateParsingException ex) {
            throw new CertificateImportException("Unable to install certificate: " + ex.getMessage(), ex);
        } catch (CertificateException | InvalidWorkerIdException | org.signserver.common.CryptoTokenOfflineException ex) {
            throw new CertificateImportException("Unable to install certificate: " + ex.getMessage(), ex);
        }
    }

    @Override
    public String generateNextKeyPair(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException {
        final AdminInfo admin = new AdminInfo(((X509CertificateAuthenticationToken) authenticationToken).getCertificate());
        try {
            final WorkerConfig config = workerSession.getCurrentWorkerConfig(internalKeyBindingId);
            String keyAlgorithm = config.getProperty(RenewalWorker.PROPERTY_KEYALG, "");
            if (keyAlgorithm.trim().isEmpty()) {
                keyAlgorithm = "RSA";
            }
            String keySpec = config.getProperty(RenewalWorker.PROPERTY_KEYSPEC, "");
            if (keySpec.trim().isEmpty()) {
                keySpec = "2048";
            }
            String nextKey = workerSession.generateSignerKey(admin, new WorkerIdentifier(internalKeyBindingId), keyAlgorithm, keySpec, null, null);
            workerSession.setWorkerProperty(admin, internalKeyBindingId, CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY, nextKey);
            workerSession.reloadConfiguration(admin, internalKeyBindingId);
            return nextKey;
        } catch (org.signserver.common.CryptoTokenOfflineException | InvalidWorkerIdException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public String renewInternallyIssuedCertificate(AuthenticationToken authenticationToken, int internalKeyBindingId, EndEntityInformation endEntityInformation) throws AuthorizationDeniedException, CryptoTokenOfflineException, CertificateImportException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<InternalKeyBindingInfo> getInternalKeyBindingInfos(AuthenticationToken authenticationToken, String internalKeyBindingType) {
        ArrayList<InternalKeyBindingInfo> results = new ArrayList<>();
        if ("AuthenticationKeyBinding".equals(internalKeyBindingType)) {
            for (int workerId : workerSession.getWorkers(WorkerType.PROCESSABLE)) {
                WorkerConfig config = workerSession.getCurrentWorkerConfig(workerId);
                if (Boolean.parseBoolean(config.getProperty(PeersWorkerProperties.PEERS_VISIBLE, Boolean.FALSE.toString())) && (config.getCryptoTokenImplementationClass() != null || !config.getProperty(CryptoTokenHelper.PROPERTY_CRYPTOTOKEN, "").isEmpty())) {
                    AuthenticationKeyBinding ikb = new AuthenticationKeyBinding();

                    // Send fingerprint for certificates issued by EJBCA
                    String certificateId = null;
                    if (Boolean.parseBoolean(config.getProperty(PeersWorkerProperties.PEERS_ISSUED, "false"))) { // Only set the fingerprint if we now it is a cert issued by EJBCA otherwise EJBCA will not show it
                        try {
                            byte[] signerCertificateBytes = workerSession.getSignerCertificateBytes(new WorkerIdentifier(workerId));
                            if (signerCertificateBytes == null) {
                                LOG.warn("PEERS_ISSUED=true but no certificate");
                            } else {
                                certificateId = CertTools.getFingerprintAsString(signerCertificateBytes);
                            }
                        } catch (org.signserver.common.CryptoTokenOfflineException ex) {
                            LOG.debug("PEERS_ISSUED=true but unable to get certificate for worker " + workerId);
                        }
                    }

                    final InternalKeyBindingStatus ikbStatus = Boolean.parseBoolean(config.getProperty(SignServerConstants.DISABLED, "FALSE")) ? InternalKeyBindingStatus.DISABLED : InternalKeyBindingStatus.ACTIVE;

                    ikb.init(workerId, config.getProperty(PropertiesConstants.NAME), ikbStatus, certificateId, workerId, config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY), new LinkedHashMap<>());
                    ikb.setNextKeyPairAlias(config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY));

                    InternalKeyBindingInfo info = new InternalKeyBindingInfo(ikb);
                    results.add(info);
                }
            }
        }
        return results;
    }

    @Override
    public InternalKeyBindingInfo getInternalKeyBindingInfo(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean setStatus(AuthenticationToken authenticationToken, int internalKeyBindingId, InternalKeyBindingStatus status) throws AuthorizationDeniedException {
        return true;
    }

    private void checkCertificateIsOkToImport(int workerId, List<Certificate> certificateChain) throws CertificateImportException, InvalidWorkerIdException {
        List<String> certificateIssues = workerSession.getCertificateIssues(workerId, certificateChain);
        if (!certificateIssues.isEmpty()) {
            LOG.info("Certificate was not accepted for worker " + workerId + ": " + certificateIssues);
            throw new CertificateImportException("Certificate chain was not accepted: " + certificateIssues);
        }
    }

}
