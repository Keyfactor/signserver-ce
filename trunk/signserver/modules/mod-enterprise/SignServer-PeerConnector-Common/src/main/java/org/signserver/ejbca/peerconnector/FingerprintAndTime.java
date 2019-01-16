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

import java.io.Serializable;

/**
 * Representation of a certificate fingerprint and the last know time it was updated at the time
 * this object was created.
 * 
 * @version $Id$
 */
public class FingerprintAndTime implements Serializable {
    
    private static final long serialVersionUID = 1L;

    private final String fingerprint;
    private final Long updateTime;
    
    public FingerprintAndTime(final String fingerprint, final Long updateTime) {
        this.fingerprint = fingerprint;
        this.updateTime = updateTime;
    }

    public String getFingerprint() { return fingerprint; }
    public Long getUpdateTime() { return updateTime; }
}
