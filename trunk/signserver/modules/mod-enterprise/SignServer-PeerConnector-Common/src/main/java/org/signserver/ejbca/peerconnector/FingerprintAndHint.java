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
 * Representation of a certificate fingerprint and an indication if the certificate exists at the
 * time the object was created.
 * 
 * @version $Id$
 */
public class FingerprintAndHint implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String fingerprint;
    private final boolean alreadyExistsHint;
    
    public FingerprintAndHint(final String fingerprint, final boolean alreadyExistsHint) {
        this.fingerprint = fingerprint;
        this.alreadyExistsHint = alreadyExistsHint;
    }

    public String getFingerprint() { return fingerprint; }
    public boolean isAlreadyExistsHint() { return alreadyExistsHint; }
}
