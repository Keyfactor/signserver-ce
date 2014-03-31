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
package org.signserver.module.renewal.worker;

import java.util.List;

import junit.framework.TestCase;

import org.signserver.common.WorkerConfig;

/**
 * Test cases for the error handling in RenewalWorker.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class RenewalWorkerUnitTest extends TestCase {

    public void test01NoTruststoreType() throws Exception {
        final List<String> fatalErrors = getFatalErrors(null, "dummypath", "foo123", null, "http://ejbca/ws");
        
        assertTrue("Should contain error", fatalErrors.contains("Missing TRUSTSTORETYPE property"));
    }

    private List<String> getFatalErrors(final String truststoreType,
            final String truststorePath, final String truststorePassword,
            final String truststoreValue, final String ejbcawsUrl) {
        final WorkerConfig config = new WorkerConfig();
        
        if (truststoreType != null) {
            config.setProperty("TRUSTSTORETYPE", truststoreType);
        }
        
        if (truststorePath != null) {
            config.setProperty("TRUSTSTOREPATH", truststorePath);
        }
        
        if (truststorePassword != null) {
            config.setProperty("TRUSTSTOREPASSWORD", truststorePassword);
        }
        
        if (truststoreValue != null) {
            config.setProperty("TRUSTSTOREVALUE", truststoreValue);
        }
        
        if (ejbcawsUrl != null) {
            config.setProperty("EJBCAWSURL", ejbcawsUrl);
        }
        
        final RenewalWorker worker = new RenewalWorker();
        
        worker.initInternal(4711, config, null, null);
        
        return worker.getLocalFatalErrors();
    }
}
