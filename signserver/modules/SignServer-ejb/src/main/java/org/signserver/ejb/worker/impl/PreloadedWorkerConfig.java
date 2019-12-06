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
package org.signserver.ejb.worker.impl;

import java.util.List;
import java.util.Properties;
import org.signserver.common.SignServerConstants;
import static org.signserver.common.SignServerConstants.DISABLED;
import static org.signserver.common.SignServerConstants.DISABLEKEYUSAGECOUNTER;
import org.signserver.common.WorkerConfig;
import static org.signserver.common.util.PropertiesConstants.NAME;

/**
 * Parsed and checked configuration.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PreloadedWorkerConfig {
    
    private final String name;
    private final boolean disabled;
    
    private final boolean disableKeyUsageCounter;
    private final long keyUsageLimit;
    private final boolean keyUsageLimitSpecified;
    
    private final boolean checkCertValidity;
    private final boolean checkPrivateKeyValidity;
    private final int minRemainingCertValidity;

    /**
     * Parse and construct the worker configuration.
     *
     * @param config to parse
     * @param fatalErrors list to add configuration errors to
     */
    protected PreloadedWorkerConfig(final WorkerConfig config, final List<String> fatalErrors) {
        this.name = config.getProperty(NAME);
        this.disabled = config.getProperty(DISABLED, "FALSE").equalsIgnoreCase("TRUE"); // TODO: Make stricter check

        this.disableKeyUsageCounter = config.getProperty(DISABLEKEYUSAGECOUNTER, "FALSE").equalsIgnoreCase("TRUE");
        long keyUsageLimitValue;
        try {
            keyUsageLimitValue = Long.valueOf(config.getProperty(SignServerConstants.KEYUSAGELIMIT, "-1"));
        } catch (NumberFormatException ex) {
            // Not adding here in fatarErrors as it will be handled at SignerLevel by BaseSigner           
            keyUsageLimitValue = -1;
        }

        this.keyUsageLimit = keyUsageLimitValue;
        this.keyUsageLimitSpecified = keyUsageLimit != -1;
        if (disableKeyUsageCounter && keyUsageLimitSpecified) {
            fatalErrors.add("Configuration error: " + SignServerConstants.DISABLEKEYUSAGECOUNTER + "=TRUE but " + SignServerConstants.KEYUSAGELIMIT + " is also configured.");
        }

        this.checkCertValidity = config.getProperty(SignServerConstants.CHECKCERTVALIDITY, Boolean.TRUE.toString()).equalsIgnoreCase(Boolean.TRUE.toString());
        this.checkPrivateKeyValidity = config.getProperty(SignServerConstants.CHECKCERTPRIVATEKEYVALIDITY, Boolean.TRUE.toString()).equalsIgnoreCase(Boolean.TRUE.toString());

        // Empty value for minRemainingCertValidity parameter gives NumberFormatExceptionError so need to handle it
        int minRemainingCertValidityValue;
        try {
            minRemainingCertValidityValue = Integer.valueOf(config.getProperty(SignServerConstants.MINREMAININGCERTVALIDITY, "0"));
        } catch (NumberFormatException ex) {
            // Not adding here in fatarErrors as it will be handled at SignerLevel
            minRemainingCertValidityValue = 0;
        }
        this.minRemainingCertValidity = minRemainingCertValidityValue;
    }

    public String getName() {
        return name;
    }

    public boolean isDisabled() {
        return disabled;
    }

    public boolean isDisableKeyUsageCounter() {
        return disableKeyUsageCounter;
    }

    public long getKeyUsageLimit() {
        return keyUsageLimit;
    }

    public boolean isKeyUsageLimitSpecified() {
        return keyUsageLimitSpecified;
    }

    public boolean isCheckCertValidity() {
        return checkCertValidity;
    }

    public boolean isCheckPrivateKeyValidity() {
        return checkPrivateKeyValidity;
    }

    public int getMinRemainingCertValidity() {
        return minRemainingCertValidity;
    }
    
}
