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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.ejb.EJB;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.SignServerContext;
import org.signserver.server.WorkerContext;
import org.signserver.server.timedservices.BaseTimedService;

/**
 * TimedService that outputs a status report for a configured set of signers.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignerStatusReportTimedService extends BaseTimedService {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(SignerStatusReportTimedService.class);

    /** Property OUTPUTFILE. **/
    private static final String PROPERTY_OUTPUTFILE = "OUTPUTFILE";

    /** Property WORKERS. **/
    static final String PROPERTY_WORKERS = "WORKERS";

    /** Output file. */
    private File outputFile;

    private SignerStatusReportBuilder reportBuilder;

    /** Workersession. */
    @EJB
    private IWorkerSession workerSession; // FIXME: Better to somehow inject this

    /**
     * Initializes the worker.
     * @param workerId Id of worker
     * @param config the configuration
     * @param workerContext the context
     * @param workerEntityManager entity manager
     */
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext,
            final EntityManager workerEntityManager) {
        super.init(workerId, config, workerContext, workerEntityManager);

        final String outputfileValue = config.getProperties()
                .getProperty(PROPERTY_OUTPUTFILE);
        if (outputfileValue != null) {
            outputFile = new File(outputfileValue);
        
            LOG.info("Output file: " + outputFile.getAbsolutePath());
        } else {
            LOG.error("Property OUTPUTFILE missing!");
        }

        List<String> workers = new LinkedList<String>();
        final String workersValue = config.getProperty(PROPERTY_WORKERS);
        if (workersValue == null) {
            LOG.error("Property WORKERS missing!");
        } else {
            workers.addAll(Arrays.asList(workersValue.split(",")));
        }
        this.reportBuilder = new SignerStatusReportBuilder(workers, getWorkerSession(), ((SignServerContext) workerContext).getKeyUsageCounterDataService());
        LOG.info("Worker[" + workerId +"]: " + "Workers: " + workers.size());
    }

    /**
     * Called to execute this timed service.
     * @see org.signserver.server.timedservices.ITimedService#work()
     * @throws ServiceExecutionFailedException in case of exception
     */
    @Override
    public final void work() throws ServiceExecutionFailedException {
        LOG.trace(">work");
        LOG.info("Worker[" + workerId + "]: Service called");

        PrintWriter out = null;
        try {
            final CharSequence report = reportBuilder.buildReport();
            out = new PrintWriter(new FileOutputStream(outputFile));
            out.print(report);

            if (out.checkError()) {
                LOG.error("Error occured trying to write output file");
            }
        } catch (IOException ex) {
            throw new ServiceExecutionFailedException(
                    "IO exception executing service " + workerId + " "
                    + ex.getMessage(), ex);
        } finally {
            if (out != null) {
                out.close();
            }
        }

        LOG.trace("<work");
    }

    private IWorkerSession getWorkerSession() {
        if (workerSession == null) {
            try {
                workerSession = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
            } catch (NamingException ex) {
                throw new RuntimeException("Unable to lookup worker session",
                        ex);
            }
        }
        return workerSession;
    }
}
