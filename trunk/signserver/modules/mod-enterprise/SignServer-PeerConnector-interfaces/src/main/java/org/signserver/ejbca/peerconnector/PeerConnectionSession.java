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
import java.util.List;
import java.util.Set;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Basic CRUD bean for PeerData objects. 
 * 
 * NOTE: This class is Enterprise only. Any moves of this class have to be mirrored in the permission file of the SVN repository.
 * 
 * @version $Id$
 *
 */
public interface PeerConnectionSession {

    static final String PEER_CONNECTION_MODULE = "peerconnector-ejb";

    /**
     * Creates an outgoing peer connection
     * 
     * @param authenticationToken an authentication token
     * @param name name of the connection
     * @param state state in which to create the peer
     * @param url URL to the peer, as a string.
     * @param a reference to the authentication key binding to use for authentication to the peer  
     * @return a PeerOutgoingInformation container containing the assigned ID
     * 
     * @throws AuthorizationDeniedException if authentication token wasn't authorized to perform this action
     */
    PeerOutgoingInformation createOutgoingPeer(AuthenticationToken authenticationToken, String name, PeerState state,
            String url, Integer authenticationKeyBindingId) throws AuthorizationDeniedException;

    /**
     * Creates an outgoing peer connection
     * 
     * @param authenticationToken an authentication token
     * @param peerOutgoingInformation an information object. ID must not be pre-set!
     * @return a PeerOutgoingInformation container containing the assigned ID
     * @throws AuthorizationDeniedException if authentication token wasn't authorized to perform this action
     */
    PeerOutgoingInformation createOutgoingPeer(AuthenticationToken authenticationToken, PeerOutgoingInformation peerOutgoingInformation)
            throws AuthorizationDeniedException;
    
    /**
     * Returns an OutgoingPeerConnection with the given ID
     * 
     * @param id the ID of the sought peer connection
     * @return an outgoing peer connection or null if not found. 
     */
    PeerOutgoingInformation find(int id);

    /**
     * @return a collection of all outgoing peers in the database that the caller is authorized to view, or an empty list if none found. 
     */
    Collection<PeerOutgoingInformation> findAllAuthorized(AuthenticationToken authenticationToken);

    /**
     * 
     * @return a list of all current incoming connections. 
     */
    List<PeerIncomingInformation> getAllIncomingConnections();
    
    /**
     * Remove a PeerData object from the database
     * 
     * @param authenticationToken an authentication token
     * @param id the ID of the object to remove
     * @return true if the operation was successful
     * 
     * @throws AuthorizationDeniedException if authentication token wasn't authorized to perform this action
     */
    boolean remove(final AuthenticationToken authenticationToken, int id) throws AuthorizationDeniedException;

    /**
     * Updates an existing object with the data in the information object
     * 
     * @param peerOutgoingInformation the information object to update with
     * 
     * @throws AuthorizationDeniedException if authentication token wasn't authorized to perform this action
     */
    void update(final AuthenticationToken authenticationToken, final PeerOutgoingInformation peerOutgoingInformation)
            throws AuthorizationDeniedException;
    
    /**
     * 
     * @return a set of all registered message types.
     */
    Set<String> getRegisteredMessageTypes();
    
    /**
     * Finds all peers of a certain name
     * 
     * @param name the name to seek for
     * @return a list of all peer sharing that name.
     */
    Collection<PeerOutgoingInformation> findByName(String name);

    /**
     * Enable or disable incoming connections globally. Additionally forces re-authentication of all incoming connections.
     * 
     * @param authenticationToken an authentication token
     * @param enabled the new state
     * @return the previous state
     * @throws AuthorizationDeniedException if authentication token wasn't authorized to perform this action
     */
    boolean setEnabledIncomingConnections(AuthenticationToken authenticationToken, boolean enabled) throws AuthorizationDeniedException;

    /** @return true if incoming connections are enabled */
    boolean isEnabledIncomingConnections();

    /**
     * Enable or disable outgoing connections globally. Additionally terminates outgoing connections if disabled.
     * 
     * @param authenticationToken an authentication token
     * @param enabled the new state
     * @return the previous state
     * @throws AuthorizationDeniedException if authentication token wasn't authorized to perform this action
     */
    boolean setEnabledOutgoingConnections(AuthenticationToken authenticationToken, boolean enabled) throws AuthorizationDeniedException;

    /** @return true if outgoing connections are enabled */
    boolean isEnabledOutgoingConnections();
}
