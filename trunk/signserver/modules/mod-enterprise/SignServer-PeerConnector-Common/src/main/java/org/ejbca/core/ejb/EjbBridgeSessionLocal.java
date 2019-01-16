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
package org.ejbca.core.ejb;

import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;

/**
 * Bridge for EJB references used by the Peers implementation.
 *
 * This is the SignServer version of the EJBCA class with the same name but only
 * with the needed methods.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface EjbBridgeSessionLocal {

    public AuthorizationSessionLocal getAuthorizationSession();

    public CryptoTokenManagementSessionLocal getCryptoTokenManagementSession();

    public InternalKeyBindingMgmtSessionLocal getInternalKeyBindingMgmtSession();
    
}
