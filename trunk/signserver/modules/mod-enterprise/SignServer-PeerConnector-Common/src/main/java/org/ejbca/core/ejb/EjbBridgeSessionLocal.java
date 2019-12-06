/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
