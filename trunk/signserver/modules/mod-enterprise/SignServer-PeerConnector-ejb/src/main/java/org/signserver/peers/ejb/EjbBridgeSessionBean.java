/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
