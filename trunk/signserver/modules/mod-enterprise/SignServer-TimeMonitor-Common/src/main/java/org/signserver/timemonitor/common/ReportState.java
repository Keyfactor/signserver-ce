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
 * The state of the reporting/publishing to SignServer.
 *
 * @author Markus Kilås
 * @version $Id$
 */
 public enum ReportState {

    /** The results were successfully published to SignServer. */
    REPORTED,

    /**
     * The results were successfully published to SignServer but the time it 
     * took to perform the measurements and publish it was longer than the time 
     * configured as timemonitor.warnRunTime.
     *
     * The log gives more information about the actual run time and how much 
     * time was spent during query and publishing when the state changes to 
     * this state.
     */
    REPORTED_BUT_EXPIRE_TIME_SHORT,

    /**
     * The results could not be published to SignServer.
     * An error message could be available in the log when the state changes to 
     * this state.
     */
    FAILED_TO_REPORT

}
