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
package org.signserver.timemonitor.ntp;

import org.signserver.timemonitor.common.LeapState;

/**
 * Holder for the result of an NTP query command.
 *
 * @author Marcus Lundblad
 * @version $Id: NTPQResult.java 4551 2012-12-07 16:33:20Z marcus $
 */

public class NTPQResult extends AbstractResult {
    private LeapState leapState;

    public NTPQResult(int exitCode, String errorMessage,
            LeapState leapState) {
        super(exitCode, errorMessage);
        this.leapState = leapState;
    }

    public LeapState getLeapState() {
        return leapState;
    }

    public void setLeapState(LeapState leapState) {
        this.leapState = leapState;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (getClass() != obj.getClass()) {
            return false;
        }

        final NTPQResult other = (NTPQResult) obj;

        if (exitCode != other.exitCode) {
            return false;
        }

        if (leapState != other.leapState) {
            return false;
        }

        if ((this.errorMessage == null) ? (other.errorMessage != null) : !this.errorMessage.equals(other.errorMessage)) {
            return false;
        }

        return true;
    }

    @Override
    public String toString() {
        return "NTPQResult{" + "exitCode=" + exitCode + ", errorMessage=" + errorMessage + ", state=" + leapState.name() + '}';
    }

}
