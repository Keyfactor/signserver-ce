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
 * Ask peer to update the certificate for an InternalKeyBinding.
 * 
 * @version $Id$
 */
public class InternalKeyBindingUpdateMessage extends PeerMessage {

    private static final long serialVersionUID = 1L;
    private static final int CURRENT_VERSION = 1;

    private final int internalKeyBindingId;
    private final byte[] encodedCertificate;
    private final CertificateEncodingType encodedCertificateType;  // Added in version 1 as of ECA-5972

    public InternalKeyBindingUpdateMessage(final int internalKeyBindingId, final byte[] encodedCertificate) {
        super(PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_UPDATE.name(), 0);
        this.internalKeyBindingId = appendPrimitiveInt(internalKeyBindingId);
        this.encodedCertificate = appendPrimitiveByteArray(encodedCertificate);
        this.encodedCertificateType = CertificateEncodingType.BINARY_CERTIFICATE;
        appendFinished();
    }

    public InternalKeyBindingUpdateMessage(final int internalKeyBindingId, final byte[] encodedCertificate, final CertificateEncodingType encodedCertificateType) {
        super(PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_UPDATE.name(), CURRENT_VERSION);
        this.internalKeyBindingId = appendPrimitiveInt(internalKeyBindingId);
        this.encodedCertificate = appendPrimitiveByteArray(encodedCertificate);
        appendPrimitiveInt(encodedCertificateType.getValue());
        this.encodedCertificateType = encodedCertificateType;
        appendFinished();
    }

    public InternalKeyBindingUpdateMessage(final PeerMessage peerMessage) {
        super(PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_UPDATE.name(), peerMessage);
        internalKeyBindingId = nextPrimitiveInt();
        encodedCertificate = nextPrimitiveByteArray();
        encodedCertificateType = getSpecificMessageVersion() == 0 ? CertificateEncodingType.BINARY_CERTIFICATE : CertificateEncodingType.fromInt(nextPrimitiveInt());
    }

    public int getInternalKeyBindingId() { return internalKeyBindingId; }
    public byte[] getEncodedCertificate() { return encodedCertificate; }
    public CertificateEncodingType getEncodedCertificateType() { return encodedCertificateType; }
}
