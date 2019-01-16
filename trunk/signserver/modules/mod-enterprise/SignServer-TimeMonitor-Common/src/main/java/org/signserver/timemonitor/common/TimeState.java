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
package org.signserver.timemonitor.common;

/**
 * The state of the time source.
 *
 * @author Markus Kilås
 * @version $Id: TimeState.java 4462 2012-11-13 08:54:00Z markus $
 */
public enum TimeState {

    /** The time is in sync as it was detected to be within the configured range. */
    INSYNC,

    /** The time is in sync but was detected to be within the configured range to give a warning. */
    SOON_OUT_OF_SYNC,

    /** The time was detected to be out of sync. */
    OUT_OF_SYNC,

    /**
     * The status of the time is unknown as the time server has not yet been
     * contacted, it could not be contacted or that some other error occurred
     * preventing the TimeMonitor from getting the status.
     */
    UNKNOWN

}
