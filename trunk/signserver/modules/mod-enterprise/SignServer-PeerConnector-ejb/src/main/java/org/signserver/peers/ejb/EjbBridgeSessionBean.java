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
package org.signserver.peers.ejb;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.signserver.peers.ejb.keybind.SignServerInternalKeyBindingMgmtSessionLocal;

/**
 * SignServer specific version of the EJB references bridge from EJBCA used by the Peers implementation.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Stateless
public class EjbBridgeSessionBean implements EjbBridgeSessionLocal {

    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    
    @EJB
    private SignServerInternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;
    
    @Override
    public AuthorizationSessionLocal getAuthorizationSession() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public CryptoTokenManagementSessionLocal getCryptoTokenManagementSession() {
        return cryptoTokenManagementSession;
    }

    @Override
    public SignServerInternalKeyBindingMgmtSessionLocal getInternalKeyBindingMgmtSession() {
        return internalKeyBindingMgmtSession;
    }
}
