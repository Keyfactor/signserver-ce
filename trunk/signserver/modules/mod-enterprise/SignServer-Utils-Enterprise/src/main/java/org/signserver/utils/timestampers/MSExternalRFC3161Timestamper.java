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
