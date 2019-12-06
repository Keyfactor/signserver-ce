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
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.ServiceContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.WorkerContext;
import org.signserver.server.timedservices.BaseTimedService;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.entities.IKeyUsageCounterDataService;

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

    private List<String> workers;
    

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

        workers = new LinkedList<>();
        final String workersValue = config.getProperty(PROPERTY_WORKERS);
        if (workersValue == null) {
            LOG.error("Property WORKERS missing!");
        } else {
            for (String workerName : workersValue.split(",")) {
                workers.add(workerName.trim());
            }
        }
        LOG.info("Worker[" + workerId +"]: " + "Workers: " + workers.size());
    }

    /**
     * Called to execute this timed service.
     * 
     * @param context Service context
     * @see org.signserver.server.timedservices.ITimedService#work()
     * @throws ServiceExecutionFailedException in case of exception
     */
    @Override
    public final void work(final ServiceContext context) throws ServiceExecutionFailedException {
        LOG.trace(">work");
        LOG.info("Worker[" + workerId + "]: Service called");

        PrintWriter out = null;
        try {
            final SignerStatusReportBuilder reportBuilder = new SignerStatusReportBuilder(workers, context.getServices().get(WorkerSessionLocal.class), context.getServices().get(IKeyUsageCounterDataService.class));
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

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final List<String> fatalErrors = new LinkedList<>();
        
        fatalErrors.addAll(super.getFatalErrors(services));
        
        if (workers.isEmpty()) {
            fatalErrors.add("Property WORKERS missing");
        }
        
        if (outputFile == null) {
            fatalErrors.add("Property OUTPUTFILE missing");
        }
        
        return fatalErrors;
    }
}
