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
package org.signserver.module.signerstatusreport;

import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.server.KeyUsageCounterHash;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounter;
import org.signserver.ejb.interfaces.WorkerSessionLocal;

/**
 * Builds a signer's status report for the choosen signers in a special format.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignerStatusReportBuilder implements ReportBuilder {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignerStatusReportBuilder.class);
    
    private static final String STATUS_ACTIVE = "ACTIVE";
    private static final String STATUS_OFFLINE = "OFFLINE";

    private static final String SEPARATOR = ", ";
    
    /** Validity date time format. */
    private final FastDateFormat dateFormat =
            FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss z");
    
    /** List of worker names. */
    private final List<String> workers;
    
    private final WorkerSessionLocal workerSession;
    private final IKeyUsageCounterDataService keyUsageCounterDataService;
    
    public SignerStatusReportBuilder(List<String> workers, WorkerSessionLocal workerSession, IKeyUsageCounterDataService keyUsageCounterDataService) {
        this.workers = workers;
        this.workerSession = workerSession;
        this.keyUsageCounterDataService = keyUsageCounterDataService;
    }
    
    @Override
    public CharSequence buildReport() {
        final StringBuilder sb = new StringBuilder();

        for (String worker : workers) {
            try {
                LOG.debug("Worker: " + worker);
                int workerId = workerSession.getWorkerId(worker);
                String statusString = STATUS_ACTIVE;
                KeyUsageCounter signings = null;
                final String pk = getKeyHash(workerId);
                if (pk == null) {
                    statusString = STATUS_OFFLINE;
                } else {

                    WorkerStatus status = null;
                    try {
                        status = workerSession.getStatus(new WorkerIdentifier(workerId));
                    } catch (InvalidWorkerIdException ex) {
                        LOG.error("Invalid worker id: " + workerId, ex);
                    }
                    if (status == null || !status.getFatalErrors().isEmpty()) {
                        statusString = STATUS_OFFLINE;
                    }
                    if (status instanceof StaticWorkerStatus &&
                            ((StaticWorkerStatus) status).getTokenStatus()
                            == WorkerStatus.STATUS_OFFLINE) {
                        statusString = STATUS_OFFLINE;
                    }


                    try {
                        signings = keyUsageCounterDataService.getCounter(pk);
                    } catch (IllegalArgumentException ex) {
                        LOG.warn(ex, ex);
                    }
                }

                sb.append("workerName=");
                sb.append(worker);
                sb.append(SEPARATOR);
                sb.append("status=");
                sb.append(statusString);
                sb.append(SEPARATOR);

                // Output validities
                Date notBefore = null;
                Date notAfter = null;
                try {
                    notBefore = workerSession.getSigningValidityNotBefore(
                            new WorkerIdentifier(workerId));
                } catch (CryptoTokenOfflineException ignored) {}
                if (notBefore != null) {
                    sb.append("validityNotBefore=");
                    sb.append(dateFormat.format(notBefore));
                    sb.append(SEPARATOR);
                }
                try {
                    notAfter = workerSession.getSigningValidityNotAfter(
                            new WorkerIdentifier(workerId));
                } catch (CryptoTokenOfflineException ignored) {}
                if (notAfter != null) {
                    sb.append("validityNotAfter=");
                    sb.append(dateFormat.format(notAfter));
                    sb.append(SEPARATOR);
                }

                if (signings != null) {
                    final long keyUsageLimit = Long.valueOf(
                            workerSession.getCurrentWorkerConfig(workerId)
                                    .getProperty(
                                            SignServerConstants.KEYUSAGELIMIT, "-1"));
                    sb.append("signings=");
                    sb.append(signings.getCounter());
                    sb.append(SEPARATOR);
                    sb.append("signLimit=");
                    sb.append(keyUsageLimit);
                    sb.append(SEPARATOR);
                }

                sb.append("\n");
            } catch (InvalidWorkerIdException ex) {
                LOG.warn("No such worker: \"" + worker + "\"");
            }
        }
        return sb;
    }

    private String getKeyHash(final int worker) {
        String ret = null;
        try {
            final Certificate cert = workerSession
                    .getSignerCertificate(new WorkerIdentifier(worker));
            if (cert != null) {
                ret = KeyUsageCounterHash.create(cert.getPublicKey());
            }
        } catch (CryptoTokenOfflineException ignored) {}
        return ret;
    }
}
