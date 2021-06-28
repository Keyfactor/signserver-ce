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
package org.signserver.server.cryptotokens;

/**
 * Base class for crypto tokens.
 * When we add new methods to the ICryptoToken:interfaces default
 * implementations can be added here.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class BaseCryptoToken implements ICryptoTokenV4 {

    @Override
    public boolean isNoCertificatesRequired() {
        return false;
    }

}
