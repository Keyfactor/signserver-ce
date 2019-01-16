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
