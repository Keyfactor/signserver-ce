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

import java.util.ArrayList;
import java.util.List;

import org.signserver.ejbca.peerconnector.PeerMessage;

/**
 * Response by peer to query on status of authorized InternalKeyBindings.
 * 
 * @version $Id$
 */
public class InternalKeyBindingStatusResponseMessage extends PeerMessage {

    private static final long serialVersionUID = 1L;

    private final List<InternalKeyBindingStatusReport> internalKeyBindingStatusReports;

    public InternalKeyBindingStatusResponseMessage(final List<InternalKeyBindingStatusReport> internalKeyBindingStatusReports) {
        super(PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_STATUS_RESPONSE.name());
        this.internalKeyBindingStatusReports = internalKeyBindingStatusReports;
        appendPrimitiveInt(internalKeyBindingStatusReports.size());
        for (final InternalKeyBindingStatusReport internalKeyBindingStatusReport : internalKeyBindingStatusReports) {
            appendObjectStringUtf8(internalKeyBindingStatusReport.getType());
            appendPrimitiveInt(internalKeyBindingStatusReport.getId());
            appendObjectStringUtf8(internalKeyBindingStatusReport.getName());
            appendObjectStringUtf8(internalKeyBindingStatusReport.getStatus());
            appendObjectStringUtf8(internalKeyBindingStatusReport.getCertificateFingerprint());
            appendPrimitiveInt(internalKeyBindingStatusReport.getCryptoTokenId());
            appendObjectStringUtf8(internalKeyBindingStatusReport.getCryptoTokenName());
            appendPrimitiveBoolean(internalKeyBindingStatusReport.isCryptoTokenActive());
            appendObjectStringUtf8(internalKeyBindingStatusReport.getCurrentKeyPairAlias());
            appendObjectStringUtf8(internalKeyBindingStatusReport.getCurrentKeyPairAlgorithm());
            appendObjectStringUtf8(internalKeyBindingStatusReport.getCurrentKeyPairSpecs());
            appendObjectStringUtf8(internalKeyBindingStatusReport.getCurrentKeyPairSubjectKeyId());
        }
        appendFinished();
    }

    public InternalKeyBindingStatusResponseMessage(final PeerMessage peerMessage) {
        super(PeerKeyBindingMessageType.INTERNAL_KEY_BINDING_STATUS_RESPONSE.name(), peerMessage);
        final int size = nextPrimitiveInt();
        internalKeyBindingStatusReports = new ArrayList<InternalKeyBindingStatusReport>(size);
        for (int i=0; i<size; i++) {
            final String type = nextObjectStringUtf8();
            final int id = nextPrimitiveInt();
            final String name = nextObjectStringUtf8();
            final String status = nextObjectStringUtf8();
            final String certificateFingerprint = nextObjectStringUtf8();
            final int cryptoTokenId = nextPrimitiveInt();
            final String cryptoTokenName = nextObjectStringUtf8();
            final boolean cryptoTokenActive = nextPrimitiveBoolean();
            final String currentKeyPairAlias = nextObjectStringUtf8();
            final String currentKeyPairAlgorithm = nextObjectStringUtf8();
            final String currentKeyPairSpecs = nextObjectStringUtf8();
            final String currentKeyPairSubjectKeyId = nextObjectStringUtf8();
            internalKeyBindingStatusReports.add(new InternalKeyBindingStatusReport(type, id, name, status, certificateFingerprint, cryptoTokenId, cryptoTokenName, cryptoTokenActive,
                    currentKeyPairAlias, currentKeyPairAlgorithm, currentKeyPairSpecs, currentKeyPairSubjectKeyId));
        }
    }

    public List<InternalKeyBindingStatusReport> getIkbStatusReports() { return internalKeyBindingStatusReports; }
}
