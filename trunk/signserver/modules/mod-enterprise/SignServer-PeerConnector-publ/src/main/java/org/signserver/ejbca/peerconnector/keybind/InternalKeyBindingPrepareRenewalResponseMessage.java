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

import org.signserver.ejbca.peerconnector.PeerMessage;

/**
 * Response to request to create and respond with a CSR for an InternalKeyBinding.
 * 
 * @version $Id$
 */
public class InternalKeyBindingPrepareRenewalResponseMessage extends PeerMessage {

    private static final long serialVersionUID = 1L;
    private static final int CURRENT_VERSION = 1;

    private final int internalKeyBindingId;
    private final boolean keysRenewed;
    private final byte[] pkcs10csr;
    private final CertificateEncodingType preferredEncodedCertificateType; // Added in version 1 as of ECA-5972
    
    public InternalKeyBindingPrepareRenewalResponseMessage(final int internalKeyBindingId, final boolean keysRenewed, final byte[] pkcs10csr) {
        super(PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_PREPARE_RENEWAL_RESPONSE.name(), 0);
        this.internalKeyBindingId = appendPrimitiveInt(internalKeyBindingId);
        this.keysRenewed = appendPrimitiveBoolean(keysRenewed);
        this.pkcs10csr = appendPrimitiveByteArray(pkcs10csr);
        this.preferredEncodedCertificateType = CertificateEncodingType.BINARY_CERTIFICATE;
        appendFinished();
    }

    public InternalKeyBindingPrepareRenewalResponseMessage(final int internalKeyBindingId, final boolean keysRenewed, final byte[] pkcs10csr, final CertificateEncodingType preferredEncodedCertificateType) {
        super(PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_PREPARE_RENEWAL_RESPONSE.name(), CURRENT_VERSION);
        this.internalKeyBindingId = appendPrimitiveInt(internalKeyBindingId);
        this.keysRenewed = appendPrimitiveBoolean(keysRenewed);
        this.pkcs10csr = appendPrimitiveByteArray(pkcs10csr);
        appendPrimitiveInt(preferredEncodedCertificateType.getValue());
        this.preferredEncodedCertificateType = preferredEncodedCertificateType;
        appendFinished();
    }

    public InternalKeyBindingPrepareRenewalResponseMessage(final PeerMessage peerMessage) {
        super(PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_PREPARE_RENEWAL_RESPONSE.name(), peerMessage);
        internalKeyBindingId = nextPrimitiveInt();
        keysRenewed = nextPrimitiveBoolean();
        pkcs10csr = nextPrimitiveByteArray();
        preferredEncodedCertificateType = getSpecificMessageVersion() == 0 ? CertificateEncodingType.BINARY_CERTIFICATE : CertificateEncodingType.fromInt(nextPrimitiveInt());
    }

    public int getInternalKeyBindingId() { return internalKeyBindingId; }
    public boolean isKeysRenewed() { return keysRenewed; }
    public byte[] getPkcs10csr() { return pkcs10csr; }
    public CertificateEncodingType getPreferredCertificateEncodingType() { return preferredEncodedCertificateType; }
}
