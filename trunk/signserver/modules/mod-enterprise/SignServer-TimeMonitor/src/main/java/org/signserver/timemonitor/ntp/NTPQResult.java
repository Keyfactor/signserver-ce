/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
