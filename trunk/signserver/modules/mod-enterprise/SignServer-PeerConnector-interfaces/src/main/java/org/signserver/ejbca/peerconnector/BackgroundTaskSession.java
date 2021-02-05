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

import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * @version $Id$
 *
 */
public interface BackgroundTaskSession {

    /**
     * 
     * @param type the task type
     * @param id if of the tast
     * @return status message if active, or null if no such task exists
     */
    String getBackgroundTaskStatus(String type, int id);
    
    /**
     * Register and start execution of a PeerSyncTask via an EJB @TimeOut
     * 
     * @param authenticationToken an authentication token
     * @param timeOutMs timeout of the task in milliseconds. 
     * @param peerOutgoingInformation the {@link PeerOutgoingInformation} to sync
     * @param issuerDns a list of issuer DNs to filter through. Set as null to ignore.
     * @param certificateProfileIds a list of certificate profiles to filter through. Set as null to ignore.
     * @param storeCertificate true for the certificate to be pushed to the peer
     * @param includeIntegrity true for data protection information to be pushed
     * @param onlyPublishRevoked true if only revoked certificates are to be pushed
     * @param ignoreUpdateTime true if sync is to ignore that certificate at peer might have a newer update time than the local one.
     * @param skipRowEstimation true to skip row estimation step.
     * @param onlyCheck Only compare local and remote data without performing any updates on the peer system. (Dry run.)
     * 
     * @throws AuthorizationDeniedException if not authorized to perform sync
     */
    boolean startPeerSyncTask(final AuthenticationToken authenticationToken, final long timeOutMs,
            final PeerOutgoingInformation peerOutgoingInformation, final List<String> issuerDns, final List<Integer> certificateProfileIds,
            final boolean storeCertificate, final boolean includeIntegrity, final boolean onlyPublishRevoked, final boolean ignoreUpdateTime,
            final boolean skipRowEstimation, final boolean onlyCheck) throws AuthorizationDeniedException;
}
