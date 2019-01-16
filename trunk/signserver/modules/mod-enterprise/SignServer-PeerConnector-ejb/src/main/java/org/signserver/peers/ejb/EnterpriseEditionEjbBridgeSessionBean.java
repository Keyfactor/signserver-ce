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

import javax.ejb.Stateless;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;

/**
 * SignServer specific version of the class from EJBCA with the same name
 * used by the peer systems implementation.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Stateless
public class EnterpriseEditionEjbBridgeSessionBean implements EnterpriseEditionEjbBridgeSessionLocal {

}
