/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.timemonitor.common;

/**
 * The state of the time source.
 *
 * @author Markus Kilås
 * @version $Id$
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
