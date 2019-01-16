/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector.client;

import java.io.Serializable;

/**
 * Connection pool statistics object.
 * 
 * @version $Id$
 */
public class PeerConnectorPoolStats implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private final int available;
    private final int leased;
    private final int max;
    private final int pending;
    
    public PeerConnectorPoolStats(int available, int leased, int max, int pending) {
        this.available = available;
        this.leased = leased;
        this.max = max;
        this.pending = pending;
    }

    public int getAvailable() { return available; }
    public int getLeased() { return leased; }
    public int getMax() { return max; }
    public int getPending() { return pending; }
}
