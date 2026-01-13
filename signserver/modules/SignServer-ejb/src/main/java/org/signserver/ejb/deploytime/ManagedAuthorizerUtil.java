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
package org.signserver.ejb.deploytime;

import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;
import org.signserver.common.WorkerConfig;

import java.util.Properties;

/**
 * Helper for parsing managed role rules etc.
 */
public class ManagedAuthorizerUtil {

    /**
     * Parser exclusively used for parsing managed REST authorization properties.
     * @param properties containing authorization rules for managed REST calls
     * @return a WorkerConfig object with certificate details and certificate matching rules properties added to it.
     */
    public static WorkerConfig parse(final Properties properties) throws IllegalArgumentException {
        Properties certProperties = new Properties();
        WorkerConfig managedCertConfig = new WorkerConfig();
        for (int i = 0; i < CompileTimeSettings.MAX_CERT_ENTRIES; i++) {
            final String issuerValue = properties.getProperty(CompileTimeSettings.ADMINCERT_PREFIX
                            + CompileTimeSettings.CERT_ISSUER
                            + CompileTimeSettings.CERT_VALUE + i);
            final String subjectValue = properties.getProperty(CompileTimeSettings.ADMINCERT_PREFIX
                    + CompileTimeSettings.CERT_SUBJECT
                    + CompileTimeSettings.CERT_VALUE + i);

            // If we do not use sanitizeDescription here, the description could end up like ${managed.admincert.description.0}
            // as this deploy property is not mandatory. Which could be confusing.
            // The description is not being displayed anywhere as of now, but this method could save us some headache in the future.
            final String description = sanitizeDescription(properties.getProperty(CompileTimeSettings.ADMINCERT_PREFIX
                    + CompileTimeSettings.CERT_DESCRIPTION + i));

            if(!(validateInput(issuerValue) && validateInput(subjectValue))) {
                continue;
            }

            final MatchIssuerWithType issuerType =
                    MatchIssuerWithType.valueOf(properties.getProperty(CompileTimeSettings.ADMINCERT_PREFIX
                            + CompileTimeSettings.CERT_ISSUER
                            + CompileTimeSettings.CERT_TYPE + i));
            final MatchSubjectWithType subjectType =
                    MatchSubjectWithType.valueOf(properties.getProperty(CompileTimeSettings.ADMINCERT_PREFIX
                            + CompileTimeSettings.CERT_SUBJECT
                            + CompileTimeSettings.CERT_TYPE + i));

            final String authNameEntry = "AUTHCLIENT" + i;
            certProperties.put(authNameEntry + CompileTimeSettings.CERT_ISSUER + CompileTimeSettings.CERT_TYPE, issuerType.name());
            certProperties.put(authNameEntry + CompileTimeSettings.CERT_ISSUER + CompileTimeSettings.CERT_VALUE, issuerValue);
            certProperties.put(authNameEntry + CompileTimeSettings.CERT_SUBJECT + CompileTimeSettings.CERT_TYPE, subjectType.name());
            certProperties.put(authNameEntry + CompileTimeSettings.CERT_SUBJECT + CompileTimeSettings.CERT_VALUE, subjectValue);
            certProperties.put(authNameEntry + CompileTimeSettings.CERT_DESCRIPTION, description);
            CertificateMatchingRule managedCertRule = new CertificateMatchingRule(subjectType, issuerType, subjectValue, issuerValue, description);
            managedCertConfig.addAuthorizedClientGen2(managedCertRule);
            managedCertConfig.setProperties(certProperties);
        }
        return managedCertConfig;
    }

    /**
     * Validate a single property.
     * @param input property to validate
     * @return true if input complies to the restrictions
     */
    public static boolean validateInput(final String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return !input.startsWith("${") || !input.endsWith("}");
    }

    /**
     * Sanitizes the description to an appropriate value if the description property has not been set or is null
     * @param description Managed REST cert rule description
     * @return a transformed string with appropriate value
     */
    public static String sanitizeDescription(final String description) {
        if (description == null || (description.startsWith("${") && description.endsWith("}"))) {
            return "";
        }
        return description;
    }

}
