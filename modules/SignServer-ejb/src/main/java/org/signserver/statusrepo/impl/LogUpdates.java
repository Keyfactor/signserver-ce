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
package org.signserver.statusrepo.impl;

/**
 * Enum with the different options for what changes to log.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public enum LogUpdates {
    /** Log all updates (even if the value was not changed). */
    ALL,
    
    /** Only log if the value was changed. */
    CHANGES,
    
    /** Never log updates. */
    NONE
}
