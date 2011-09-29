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
package org.signserver.server.signers;

import java.security.cert.Certificate;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.CryptoTokenStatus;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseProcessable;
import org.signserver.server.KeyUsageCounter;

/**
 * Base class that all signers can extend to cover basic in common
 * functionality.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public abstract class BaseSigner extends BaseProcessable implements ISigner {

    /**
     * @see org.signserver.server.IProcessable#getStatus()
     */
    @Override
    public WorkerStatus getStatus() {
        SignerStatus retval = null;

        try {
            final Certificate cert = getSigningCertificate();
            final long keyUsageLimit = Long.valueOf(config.getProperty(SignServerConstants.KEYUSAGELIMIT, "-1"));

            if (cert != null) {
                KeyUsageCounter counter = em.find(KeyUsageCounter.class,
                        KeyUsageCounter.createKeyHash(cert.getPublicKey()));
                int status = getCryptoToken().getCryptoTokenStatus();
                if (counter == null || keyUsageLimit != -1
                        && status == CryptoTokenStatus.STATUS_ACTIVE
                        && counter.getCounter() >= keyUsageLimit) {
                    status = CryptoTokenStatus.STATUS_OFFLINE;
                }

                if (counter != null) {
                    retval = new SignerStatus(workerId, status, new ProcessableConfig(config), cert, counter.getCounter());
                } else {
                    retval = new SignerStatus(workerId, status, new ProcessableConfig(config), cert);
                }
            } else {
                retval = new SignerStatus(workerId, getCryptoToken().getCryptoTokenStatus(), new ProcessableConfig(config), cert);
            }
        } catch (CryptoTokenOfflineException e) {
            retval = new SignerStatus(workerId, getCryptoToken().getCryptoTokenStatus(), new ProcessableConfig(config), null);
        }
        return retval;
    }
}
