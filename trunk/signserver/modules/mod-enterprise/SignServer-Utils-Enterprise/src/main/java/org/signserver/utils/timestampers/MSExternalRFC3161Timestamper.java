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

/**
 * External RFC3161 time-stamper MS style.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MSExternalRFC3161Timestamper extends ExternalRFC3161Timestamper {

    public MSExternalRFC3161Timestamper(final ASN1ObjectIdentifier policy, String username, String password) {
        super(policy, username, password);
    }

    public MSExternalRFC3161Timestamper(final ASN1ObjectIdentifier policy, String username, String password, boolean useStandardCMS) {
        super(policy, username, password, useStandardCMS);
    }
    
    
}
