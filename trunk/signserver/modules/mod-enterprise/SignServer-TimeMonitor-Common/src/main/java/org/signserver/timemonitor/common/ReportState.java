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
 * The state of the reporting/publishing to SignServer.
 *
 * @author Markus Kilås
 * @version $Id: ReportState.java 4462 2012-11-13 08:54:00Z markus $
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
