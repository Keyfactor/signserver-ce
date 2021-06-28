/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.peers.ejb.keybind;

import javax.ejb.Local;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;

/**
 * SignServer specific version of the class from EJBCA used by the peer systems implementation.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Local
public interface SignServerInternalKeyBindingMgmtSessionLocal extends InternalKeyBindingMgmtSessionLocal {
    
    void importCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId, byte[] certificate, int type) throws AuthorizationDeniedException, CertificateImportException;
}
