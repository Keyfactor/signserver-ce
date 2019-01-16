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
package org.signserver.module.msauthcode.signer;

import java.util.Collection;
import org.signserver.common.WorkerConfig;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;

/**
 * Handling of common options for MSAuthCodeSigner and MSAuthCodeCMSSigner.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MSAuthCodeOptions {

    private String programName;
    private String programURL;
    
    public static final String PROGRAM_NAME = "PROGRAM_NAME";
    public static final String PROGRAM_URL = "PROGRAM_URL";
    public static final String ALLOW_PROGRAM_NAME_OVERRIDE = "ALLOW_PROGRAM_NAME_OVERRIDE";
    public static final String ALLOW_PROGRAM_URL_OVERRIDE = "ALLOW_PROGRAM_URL_OVERRIDE";
    
    private static final boolean DEFAULT_ALLOW_PROGRAM_NAME_OVERRIDE = false;
    private static final boolean DEFAULT_ALLOW_PROGRAM_URL_OVERRIDE = false;
    private boolean allowProgramNameOverride;
    private boolean allowProgramURLOverride;

    /**
     * Parse and validate worker configuration for Authenticode-specific
     * configuration options.
     * 
     * @param config Worker configuration
     * @param configErrors Error collection to be updated with config errors
     */
    public void parse(final WorkerConfig config,
                      final Collection<String> configErrors) {
        programName = config.getProperty(PROGRAM_NAME, DEFAULT_NULL);
        programURL = config.getProperty(PROGRAM_URL, DEFAULT_NULL);
        
        String s = config.getProperty(ALLOW_PROGRAM_NAME_OVERRIDE, Boolean.toString(DEFAULT_ALLOW_PROGRAM_NAME_OVERRIDE)).trim();
        if ("true".equalsIgnoreCase(s)) {
            allowProgramNameOverride = true;
        } else if ("false".equalsIgnoreCase(s)) {
            allowProgramNameOverride = false;
        } else {
            configErrors.add("Incorrect value for " + ALLOW_PROGRAM_NAME_OVERRIDE);
        }
        
        s = config.getProperty(ALLOW_PROGRAM_URL_OVERRIDE, Boolean.toString(DEFAULT_ALLOW_PROGRAM_URL_OVERRIDE)).trim();
        if ("true".equalsIgnoreCase(s)) {
            allowProgramURLOverride = true;
        } else if ("false".equalsIgnoreCase(s)) {
            allowProgramURLOverride = false;
        } else {
            configErrors.add("Incorrect value for " + ALLOW_PROGRAM_URL_OVERRIDE);
        } 
    }

    public String getProgramName() {
        return programName;
    }

    public String getProgramURL() {
        return programURL;
    }

    public boolean isAllowProgramNameOverride() {
        return allowProgramNameOverride;
    }

    public boolean isAllowProgramURLOverride() {
        return allowProgramURLOverride;
    }
}
