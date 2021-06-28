/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.serviceprovider.impl;

import java.util.LinkedList;
import java.util.List;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.signserver.ejbca.peerconnector.PeerConnectorInRegistry;
import org.signserver.ejbca.peerconnector.PeerIncomingInformation;
import org.signserver.serviceprovider.PeersInInfo;
import org.signserver.serviceprovider.PeersProvider;

/**
 * Imlementation of PeersProvider interface using the EJBCA peers integration.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class PeersProviderImpl implements PeersProvider {

    @Override
    public List<PeersInInfo> createPeersIncoming() {
        final List<PeerIncomingInformation> incoming =
                PeerConnectorInRegistry.INSTANCE.getPeerIncomingInformations();
        final List<PeersInInfo> result = new LinkedList<>();

        incoming.stream().map((in) -> {
            final PeersInInfo pii =
                    new PeersInInfo(in.getId(), in.getAuthenticationToken());
            pii.setLastUpdate(in.getLastUpdate());
            pii.setRemoteAddress(in.getRemoteAddress());
            return pii;
        }).forEachOrdered((pii) -> {
            result.add(pii);
        });

        return result;
    }

    @Override
    public void removeIncomingPeer(final Integer id,
                       final AuthenticationToken authenticationToken) {
        PeerConnectorInRegistry.INSTANCE.remove(id, authenticationToken);
    }
}
