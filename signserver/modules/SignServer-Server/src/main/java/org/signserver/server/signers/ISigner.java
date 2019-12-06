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
package org.signserver.server.signers;

import org.signserver.server.IProcessable;

/**
 * ISigner is an interface that all signers should implement
 * 
 * There exists a BaseSigner that can be extended covering some of it's functions
 * 
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public interface ISigner extends IProcessable {
}
