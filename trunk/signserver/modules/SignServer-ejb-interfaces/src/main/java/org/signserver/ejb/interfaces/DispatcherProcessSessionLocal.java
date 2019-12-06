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
package org.signserver.ejb.interfaces;

import javax.ejb.Local;

/**
 * Interface for the dispatcher process session bean that should be used by
 * dispatchers.
 *
 * @version $Id: IDispatcherWorkerSession.java 6942 2015-12-25 17:55:39Z netmackan $
 * @see ProcessSessionLocal
 */
@Local
public interface DispatcherProcessSessionLocal extends ProcessSessionLocal {
    
}
