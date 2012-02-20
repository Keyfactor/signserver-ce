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
package org.signserver.statusrepo.common;

/**
 * Enum with all names of status properties.
 *
 * New status properties should be added to this Enum.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public enum StatusName {
    
    /** Status property set by the StartServicesServlet with the current time as value. */
    SERVER_STARTED,
    
    /** Status property used by unit tests or for any purpose. */
    TEST_PROPERTY1,
    
    /** Status property used by unit tests or for any purpose. */
    TEST_PROPERTY2,
    
    /** Status property used by unit tests or for any purpose. */
    TEST_PROPERTY3,
    
    /** 
     * Status property indicating if time source 0 is detected to be in sync. 
     * Read by the StatusReadingLocalComputerTimeSource and set by external 
     * script or some future timed service.
     */
    TIMESOURCE0_INSYNC
    
}
