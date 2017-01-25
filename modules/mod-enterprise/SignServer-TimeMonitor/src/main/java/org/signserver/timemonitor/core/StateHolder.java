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
package org.signserver.timemonitor.core;

/**
 * Implementors of this interface are able to return the current states and
 * the last updated time.
 *
 * @author Markus Kilås
 * @version $Id: StateHolder.java 4569 2012-12-10 14:11:57Z marcus $
 */
public interface StateHolder {

    /**
     * @return The complete state of the TimeMonitor as one line in the state
     * format
     */
    StringBuilder getStateLine();
}
