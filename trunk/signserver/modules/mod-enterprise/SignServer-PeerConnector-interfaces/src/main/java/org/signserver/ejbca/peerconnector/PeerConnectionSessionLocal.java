/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector;

import java.util.Collection;

import javax.ejb.Local;

/**
 * Local interface for PeerDataSession.
 * 
 * NOTE: This class is Enterprise only. Any moves of this class have to be mirrored in the permission file of the SVN repository.
 * 
 * @version $Id$
 *
 */
@Local
public interface PeerConnectionSessionLocal extends PeerConnectionSession {

    /**
     * 
     * @return a collection of all outgoing peers in the database, or an empty list if none found. 
     */
    Collection<PeerOutgoingInformation> findAll();

    /** 
     * @param authenticationToken an authentication token
     * @param peerConnection the peer connection to add or update
     * @return the ID if the added/updated peer connection.
     */
    void createOrUpdate(final PeerOutgoingInformation peerConnection);

    /** Flush the cache of outgoing peer connectors */
    void flushCache();
}
