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
package org.signserver.module.jarchive.signer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import static org.signserver.module.jarchive.signer.JArchiveSigner.PROPERTY_KEEPSIGNATURES;
import static org.signserver.module.jarchive.signer.JArchiveSigner.PROPERTY_REPLACESIGNATURE;
import static org.signserver.module.jarchive.signer.JArchiveSigner.PROPERTY_SIGNATURE_NAME_TYPE;
import static org.signserver.module.jarchive.signer.JArchiveSigner.PROPERTY_SIGNATURE_NAME_VALUE;
import static org.signserver.module.jarchive.signer.JArchiveSigner.PROPERTY_ZIPALIGN;
import static org.signserver.module.jarchive.signer.JArchiveSigner.convertToValidSignatureName;

/**
 * Configuration options for JAR signing.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class JArchiveOptions {
    
    // Default options
    private static final boolean DEFAULT_ZIPALIGN = false;
    private static final boolean DEFAULT_KEEPSIGNATURES = true;
    private static final boolean DEFAULT_REPLACESIGNATURE = true;
    private static final JArchiveSigner.SignatureNameType DEFAULT_SIGNATURE_NAME_TYPE = JArchiveSigner.SignatureNameType.KEYALIAS;
    
    private final boolean zipAlign;
    private final boolean keepSignatures;
    private final boolean replaceSignature;
    private JArchiveSigner.SignatureNameType signatureNameType;
    private String signatureNameValue;

    private final List<String> configErrors = new ArrayList<>();
    
    public JArchiveOptions(final Properties config) {
        this((Map) config);
    }

    public JArchiveOptions(final Map<String, String> config) {
        // Optional property ZIPALIGN
        String value = config.get(PROPERTY_ZIPALIGN);
        if (value == null || value.trim().isEmpty()) {
            zipAlign = DEFAULT_ZIPALIGN;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(value.trim())) {
            zipAlign = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(value.trim())) {
            zipAlign = false;
        } else {
            configErrors.add("Incorrect value for property " + PROPERTY_ZIPALIGN);
            zipAlign = DEFAULT_ZIPALIGN;
        }

        // Optional property KEEPSIGNATURES
        value = config.get(PROPERTY_KEEPSIGNATURES);
        if (value == null || value.trim().isEmpty()) {
            keepSignatures = DEFAULT_KEEPSIGNATURES;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(value.trim())) {
            keepSignatures = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(value.trim())) {
            keepSignatures = false;
        } else {
            configErrors.add("Incorrect value for property " + PROPERTY_KEEPSIGNATURES);
            keepSignatures = DEFAULT_KEEPSIGNATURES;
        }

        // Optional property REPLACESIGNATURE
        value = config.get(PROPERTY_REPLACESIGNATURE);
        if (value == null || value.trim().isEmpty()) {
            replaceSignature = DEFAULT_REPLACESIGNATURE;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(value.trim())) {
            replaceSignature = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(value.trim())) {
            replaceSignature = false;
        } else {
            configErrors.add("Incorrect value for property " + PROPERTY_REPLACESIGNATURE);
            replaceSignature = DEFAULT_REPLACESIGNATURE;
        }

        // Optional property SIGNATURE_NAME_TYPE
        try {
            value = config.get(PROPERTY_SIGNATURE_NAME_TYPE);
            if (value == null || value.trim().isEmpty()) {
                signatureNameType = DEFAULT_SIGNATURE_NAME_TYPE;
            } else {
                signatureNameType = JArchiveSigner.SignatureNameType.valueOf(value.trim());
            }

            // Conditionally optional property SIGNATURE_NAME_VALUE
            signatureNameValue = config.get(PROPERTY_SIGNATURE_NAME_VALUE);
            if (signatureNameValue == null || signatureNameValue.trim().isEmpty()) {
                signatureNameValue = null;
            }
            switch (signatureNameType) {
                // Expect no value for KEYALIAS
                case KEYALIAS: {
                    if (signatureNameValue != null) {
                        configErrors.add("No value for " + PROPERTY_SIGNATURE_NAME_VALUE + " expected when " + PROPERTY_SIGNATURE_NAME_TYPE + " is " + JArchiveSigner.SignatureNameType.KEYALIAS);
                    }
                    break;
                }

                // Require value for VALUE
                case VALUE: {
                    if (signatureNameValue == null) {
                        configErrors.add("Missing value for " + PROPERTY_SIGNATURE_NAME_VALUE + " when " + PROPERTY_SIGNATURE_NAME_TYPE + " is " + JArchiveSigner.SignatureNameType.VALUE);
                    } else {
                        String cleanedValue = convertToValidSignatureName(signatureNameValue);
                        if (!cleanedValue.equals(signatureNameValue)) {
                            configErrors.add("Incorrect value for property " + PROPERTY_SIGNATURE_NAME_VALUE + ". Valid values are maximum 8 characters from 'A-Z0-9_-.'. Use the following value: " + cleanedValue);
                            signatureNameValue = cleanedValue;
                        }
                    }
                }
            }
        } catch (IllegalArgumentException ex) {
            configErrors.add("Incorrect value for property " + PROPERTY_SIGNATURE_NAME_TYPE + ". Possible values are: " + Arrays.asList(JArchiveSigner.SignatureNameType.values()));
            signatureNameType = DEFAULT_SIGNATURE_NAME_TYPE;
        }
    }

    public boolean isZipAlign() {
        return zipAlign;
    }

    public boolean isKeepSignatures() {
        return keepSignatures;
    }

    public boolean isReplaceSignature() {
        return replaceSignature;
    }

    public JArchiveSigner.SignatureNameType getSignatureNameType() {
        return signatureNameType;
    }

    public String getSignatureNameValue() {
        return signatureNameValue;
    }

    public List<String> getConfigErrors() {
        return configErrors;
    }

}
