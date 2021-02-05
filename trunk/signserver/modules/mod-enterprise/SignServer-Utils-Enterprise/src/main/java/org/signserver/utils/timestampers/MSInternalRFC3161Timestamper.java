/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.utils.timestampers;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;

/**
 * Internal RFC3161 time-stamper MS style.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MSInternalRFC3161Timestamper extends InternalRFC3161Timestamper {
    
    public MSInternalRFC3161Timestamper(String tsaWorkerNameOrId, final ASN1ObjectIdentifier policy, String username, String password, InternalProcessSessionLocal workerSession) {
        super(tsaWorkerNameOrId, policy, username, password, workerSession);
    }
    
}
