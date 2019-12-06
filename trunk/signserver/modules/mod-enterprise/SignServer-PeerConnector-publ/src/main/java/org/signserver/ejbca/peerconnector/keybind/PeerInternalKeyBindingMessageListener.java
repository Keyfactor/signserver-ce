/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector.keybind;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyPairInfo;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;
import org.signserver.ejbca.peerconnector.GenericErrorResponseMessage;
import org.signserver.ejbca.peerconnector.PeerMessage;
import org.signserver.ejbca.peerconnector.PeerMessageListener;
import org.signserver.peers.ejb.keybind.SignServerInternalKeyBindingMgmtSessionLocal;

/**
 * Handler for incoming Peer IKB messages.
 * 
 * @version $Id$
 */
public class PeerInternalKeyBindingMessageListener implements PeerMessageListener {

    private static final AuthenticationToken alwaysAllowAuthenticationToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(PeerInternalKeyBindingMessageListener.class.getSimpleName()));
    private static final Logger log = Logger.getLogger(PeerInternalKeyBindingMessageListener.class);

    @Override
    public List<String> getSupportedMessageTypes() {
        return Arrays.asList(
                PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_STATUS_REQUEST.name(),
                PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_PREPARE_RENEWAL.name(),
                PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_UPDATE.name()
                );
    }

    @Override
    public PeerMessage receiveAndRespond(PeerMessage peerMessage, final EjbBridgeSessionLocal ejbBridgeSession,
            final EnterpriseEditionEjbBridgeSessionLocal enterpriseEditionEjbBridgeSession) {
        final PeerKeyBindingMessageType messageType = PeerKeyBindingMessageType.valueOf(peerMessage.getMessageType());
        switch (messageType) {
        case INTERNAL_KEY_BINDING_STATUS_REQUEST:
            return ikbStatusRequest(peerMessage, ejbBridgeSession);
        case INTERNAL_KEY_BINDING_PREPARE_RENEWAL:
            return ikbRenewalRequest(peerMessage, ejbBridgeSession);
        case INTERNAL_KEY_BINDING_UPDATE:
            return ikbUpdateRequest(peerMessage, ejbBridgeSession);
        default:
        }
        return null;
    }
    
    private PeerMessage ikbStatusRequest(final PeerMessage peerMessage, final EjbBridgeSessionLocal ejbBridgeSession) {
        final CryptoTokenManagementSessionLocal cryptoTokenManagementSession = ejbBridgeSession.getCryptoTokenManagementSession();
        final InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession = ejbBridgeSession.getInternalKeyBindingMgmtSession();
        final Set<String> internalKeyBindingTypes = internalKeyBindingMgmtSession.getAvailableTypesAndProperties().keySet();
        final List<InternalKeyBindingStatusReport> internalKeyBindingStatusReports = new ArrayList<>();
        for (final String internalKeyBindingType : internalKeyBindingTypes) {
            final List<InternalKeyBindingInfo> internalKeyBindingInfos = internalKeyBindingMgmtSession.getInternalKeyBindingInfos(peerMessage.getAuthenticationToken(), internalKeyBindingType);
            for (InternalKeyBindingInfo internalKeyBindingInfo : internalKeyBindingInfos) {
                final String type = internalKeyBindingInfo.getImplementationAlias();
                final int id = internalKeyBindingInfo.getId();
                final String name = internalKeyBindingInfo.getName();
                final String status = internalKeyBindingInfo.getStatus().name();
                final String certificateFingerprint = internalKeyBindingInfo.getCertificateId();
                final int cryptoTokenId = internalKeyBindingInfo.getCryptoTokenId();
                final String cryptoTokenName = name;
                boolean cryptoTokenActive = cryptoTokenManagementSession.isCryptoTokenStatusActive(internalKeyBindingInfo.getCryptoTokenId());
                String currentKeyPairAlias = internalKeyBindingInfo.getKeyPairAlias();
                String currentKeyPairAlgorithm = null;
                String currentKeyPairSpecs = null;
                String currentKeyPairSubjectKeyId = null;
                if (cryptoTokenActive) {
                    try {
                        final KeyPairInfo keyPairInfo = cryptoTokenManagementSession.getKeyPairInfo(alwaysAllowAuthenticationToken, cryptoTokenId, currentKeyPairAlias);
                        currentKeyPairAlgorithm = keyPairInfo.getKeyAlgorithm();
                        currentKeyPairSpecs = keyPairInfo.getKeySpecification();
                        currentKeyPairSubjectKeyId = keyPairInfo.getSubjectKeyID();
                    } catch (CryptoTokenOfflineException e) {
                        // Maybe we have a next key-pair already
                        try {
                            currentKeyPairAlias = internalKeyBindingInfo.getNextKeyPairAlias();
                            final KeyPairInfo keyPairInfo = cryptoTokenManagementSession.getKeyPairInfo(alwaysAllowAuthenticationToken, cryptoTokenId, currentKeyPairAlias);
                            currentKeyPairAlgorithm = keyPairInfo.getKeyAlgorithm();
                            currentKeyPairSpecs = keyPairInfo.getKeySpecification();
                            currentKeyPairSubjectKeyId = keyPairInfo.getSubjectKeyID();
                        } catch (CryptoTokenOfflineException ex2) {
                            // No longer available
                            cryptoTokenActive = false;
                        } catch (AuthorizationDeniedException e2) {
                            // Should never happen
                            throw new IllegalStateException(e);
                        }
                    } catch (AuthorizationDeniedException e) {
                        // Should never happen
                        throw new IllegalStateException(e);
                    }
                }
                internalKeyBindingStatusReports.add(new InternalKeyBindingStatusReport(type, id, name, status, certificateFingerprint, cryptoTokenId, cryptoTokenName, cryptoTokenActive,
                        currentKeyPairAlias, currentKeyPairAlgorithm, currentKeyPairSpecs, currentKeyPairSubjectKeyId));
            }
        }
        return new InternalKeyBindingStatusResponseMessage(internalKeyBindingStatusReports);
    }

    private PeerMessage ikbRenewalRequest(final PeerMessage peerMessage, final EjbBridgeSessionLocal ejbBridgeSession) {
        final InternalKeyBindingPrepareRenewalMessage peerMessageIn = new InternalKeyBindingPrepareRenewalMessage(peerMessage);
        final int internalKeyBindingId = peerMessageIn.getInternalKeyBindingId();
        final boolean renewKeysIfNeeded = peerMessageIn.isRenewKeys();
        final InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession = ejbBridgeSession.getInternalKeyBindingMgmtSession();
        try {
            if (renewKeysIfNeeded) {
                internalKeyBindingMgmtSession.generateNextKeyPair(peerMessageIn.getAuthenticationToken(), internalKeyBindingId);
            }
            try {
                final byte[] pkcs10csr = internalKeyBindingMgmtSession.generateCsrForNextKey(peerMessageIn.getAuthenticationToken(), internalKeyBindingId, null);
                return new InternalKeyBindingPrepareRenewalResponseMessage(internalKeyBindingId, renewKeysIfNeeded, pkcs10csr, CertificateEncodingType.PEM_CERTIFICATES);
            } catch (CryptoTokenOfflineException e) {
                log.error("CSR generation request from peer failed for IKB with id " + internalKeyBindingId + ".", e);
                return new GenericErrorResponseMessage(e);
            } catch (AuthorizationDeniedException e) {
                log.error("CSR generation request from peer failed for IKB with id " + internalKeyBindingId + ".", e);
                return new GenericErrorResponseMessage(e);
            }
        } catch (InvalidKeyException e) {
            log.error("Key renewal request from peer failed for IKB with id " + internalKeyBindingId + ".", e);
            return new GenericErrorResponseMessage(e);
        } catch (CryptoTokenOfflineException e) {
            log.error("Key renewal request from peer failed for IKB with id " + internalKeyBindingId + ".", e);
            return new GenericErrorResponseMessage(e);
        } catch (InvalidAlgorithmParameterException e) {
            log.error("Key renewal request from peer failed for IKB with id " + internalKeyBindingId + ".", e);
            return new GenericErrorResponseMessage(e);
        } catch (AuthorizationDeniedException e) {
            log.error("Key renewal request from peer failed for IKB with id " + internalKeyBindingId + ".", e);
            return new GenericErrorResponseMessage(e);
        }
    }

    private PeerMessage ikbUpdateRequest(final PeerMessage peerMessage, final EjbBridgeSessionLocal ejbBridgeSession) {
        final InternalKeyBindingUpdateMessage peerMessageIn = new InternalKeyBindingUpdateMessage(peerMessage);
        final int internalKeyBindingId = peerMessageIn.getInternalKeyBindingId();
        final byte[] encodedCertificate = peerMessageIn.getEncodedCertificate();
        final CertificateEncodingType type = peerMessageIn.getEncodedCertificateType();
        final SignServerInternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession = (SignServerInternalKeyBindingMgmtSessionLocal) ejbBridgeSession.getInternalKeyBindingMgmtSession();
        try {
            internalKeyBindingMgmtSession.importCertificateForInternalKeyBinding(peerMessageIn.getAuthenticationToken(), internalKeyBindingId, encodedCertificate, type.getValue());
            internalKeyBindingMgmtSession.setStatus(peerMessageIn.getAuthenticationToken(), internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
            return new PeerMessage(PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_UPDATE_RESPONSE.name());
        } catch (CertificateImportException e) {
            log.error("Update certificate request from peer failed for IKB with id " + internalKeyBindingId + ".", e);
            return new GenericErrorResponseMessage(e);
        } catch (AuthorizationDeniedException e) {
            log.error("Update certificate request from peer failed for IKB with id " + internalKeyBindingId + ".", e);
            return new GenericErrorResponseMessage(e);
        }
    }
}
