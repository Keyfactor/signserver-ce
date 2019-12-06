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

/**
 * Base class for NTP command results
 *
 * @author Marcus Lundblad
 * @version $Id: AbstractResult.java 4508 2012-12-05 08:09:52Z marcus $
 */
public abstract class AbstractResult {
    protected int exitCode;
    protected String errorMessage;

    AbstractResult(int exitCode, final String errorMessage) {
        this.exitCode = exitCode;
        this.errorMessage = errorMessage;
    }

    public int getExitCode() {
        return exitCode;
    }

    public void setExitCode(int exitCode) {
        this.exitCode = exitCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
