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
package org.signserver.serviceprovider;

import java.util.List;
import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Interface to implement for exposing peer systems functionallity to the
 * admin web GUI.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface PeersProvider {
    List<PeersInInfo> createPeersIncoming();
    void removeIncomingPeer(Integer id, AuthenticationToken authenticationToken);
}
