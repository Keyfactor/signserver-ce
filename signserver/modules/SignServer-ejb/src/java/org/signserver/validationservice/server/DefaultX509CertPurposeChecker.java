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
package org.signserver.validationservice.server;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import org.signserver.common.WorkerConfig;
import org.signserver.validationservice.common.ValidationServiceConstants;

/**
 * Default Certificate Type Checker used check the key usage against 
 * standard X509 V3 certificates.
 * 
 * @author Philip Vendil 1 dec 2007
 * @version $Id$
 */
public class DefaultX509CertPurposeChecker implements ICertPurposeChecker {

    /**
     * Does the following checks
     * <p>
     * If the certificate have certType : IDENTIFICATION it checks for
     * key usages digital signature and key encipherment
     * </p>
     * <p>
     * If the certificate have certType : ELECTRONIC_SIGNATURE it checks for
     * key usage non-repudiation
     * </p>
     * @see org.signserver.validationservice.server.ICertPurposeChecker#checkCertPurposes(org.signserver.validationservice.common.ICertificate, String[])
     */
    public String[] checkCertPurposes(Certificate cert, String[] certPurposes) {
        String[] retval = null;

        for (String certPurpose : certPurposes) {
            ArrayList<String> approvedCertPurposes = new ArrayList<String>();
            if (cert instanceof java.security.cert.X509Certificate) {
                java.security.cert.X509Certificate c = (X509Certificate) cert;
                if (certPurpose.equalsIgnoreCase(ValidationServiceConstants.CERTPURPOSE_IDENTIFICATION)) {
                    if (c.getKeyUsage() != null && c.getKeyUsage()[0] == true && c.getKeyUsage()[2] == true) {
                        approvedCertPurposes.add(certPurpose);
                    }
                } else if (certPurpose.equalsIgnoreCase(ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE)) {
                    if (c.getKeyUsage() != null && c.getKeyUsage()[1] == true) {
                        approvedCertPurposes.add(certPurpose);
                    }
                }
            }
            if (approvedCertPurposes.size() > 0) {
                retval = approvedCertPurposes.toArray(new String[approvedCertPurposes.size()]);
            }
        }
        return retval;
    }

    /**
     * @see org.signserver.validationservice.server.ICertPurposeChecker#init(org.signserver.common.WorkerConfig)
     */
    public void init(WorkerConfig config) {
        // Not used
    }
}
