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
package org.signserver.admin.cli.defaultimpl;

import java.io.ByteArrayInputStream;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import static org.signserver.common.util.PropertiesConstants.SIGNERCERT;
import static org.signserver.common.util.PropertiesConstants.SIGNERCERTCHAIN;

/**
 * Gets the current configuration of the given signer, this might not be the same as
 * the active configuration.
 *
 * @version $Id$
 */
public class GetConfigCommand extends AbstractAdminCommand {
    private static final Logger LOG = Logger.getLogger(GetConfigCommand.class);  
    
    private AdminCommandHelper helper = new AdminCommandHelper();

    @Override
    public String getDescription() {
        return "Get the configuration either global or for a worker";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver getconfig <workerid | workerName | global> \n"
                    + "Example 1 : signserver getconfig 1 \n"
                    + "Example 2 : signserver getconfig mySigner \n"
                    + "Example 3 : signserver getconfig global \n\n";
    }
    
    @Override
    public int execute(String[] args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        
        if (args.length != 1) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {
            String workerid = args[0];

            if (workerid.substring(0, 1).matches("\\d")) {
                displayWorkerConfig(Integer.parseInt(workerid));
            } else {
                if (workerid.trim().equalsIgnoreCase("GLOBAL")) {
                    // global configuration is requested
                    displayGlobalConfiguration();

                } else {
                    // named worker is requested
                    int id = helper.getWorkerSession().getWorkerId(workerid);
                    if (id == 0) {
                        throw new IllegalCommandArgumentsException("Error: No worker with the given name could be found");
                    }
                    displayWorkerConfig(id);
                }
            }
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
        return 0;
    }

    private void displayGlobalConfiguration() throws RemoteException, Exception {
        GlobalConfiguration gc = helper.getGlobalConfigurationSession().getGlobalConfiguration();
        Enumeration<String> en = gc.getKeyEnumeration();
        System.out.println("out = " + out.getClass());
        out.println(" This node has the following Global Configuration:");
        while (en.hasMoreElements()) {
            String key = en.nextElement();
            out.println("   Key : " + key + " Value : " + gc.getProperty(key));
        }
    }

    private void displayWorkerConfig(int workerId) throws RemoteException, Exception {
        final Properties config = helper.getWorkerSession().exportWorkerConfig(workerId);

        out.println(
                "OBSERVE that this command displays the current configuration which\n"
                + "doesn't have to be the same as the active configuration.\n"
                + "Configurations are activated with the reload command. \n\n"
                + "The current configuration of worker with id : " + workerId + " is :");


        if (config.size() == 0) {
            out.println("  No properties exists in the current configuration\n");
        }

        Enumeration<?> propertyKeys = config.keys();
        while (propertyKeys.hasMoreElements()) {
            String key = (String) propertyKeys.nextElement();
            out.println("  " + key + "=" + config.getProperty(key) + "\n");
        }

        if (getSignerCertificate(config) != null) {
            out.println(" The current configuration use the following signer certificate : \n");
            WorkerStatus.printCert(getSignerCertificate(config), out);
        } else {
            out.println(" Either this isn't a Signer or no Signer Certificate have been uploaded to it.\n");
        }
    }

    /**
     * Method used to fetch a signers certificate from the config
     * @return the signer certificate stored or null if no certificate have been uploaded.
     * 
     */
    private X509Certificate getSignerCertificate(final Properties config) {
        X509Certificate result = null;
        String stringcert = (String) config.get(SIGNERCERT);
        if (stringcert == null || stringcert.equals("")) {
            stringcert = (String) config.get(WorkerConfig.getNodeId() + "." + SIGNERCERT);
        }

        if (stringcert != null && !stringcert.equals("")) {
            Collection<?> certs;
            try {
                certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(stringcert.getBytes()));
                if (certs.size() > 0) {
                    result = (X509Certificate) certs.iterator().next();
                }
            } catch (CertificateException | IllegalStateException e) {
                LOG.error(e);
            }

        }

        if (result == null) {
            // try fetch certificate from certificate chain
            Collection<?> chain = getSignerCertificateChain(config);
            if (chain != null) {
                Iterator<?> iter = chain.iterator();
                while (iter.hasNext()) {
                    X509Certificate next = (X509Certificate) iter.next();
                    if (next.getBasicConstraints() == -1) {
                        result = next;
                    }
                }
            }
        }
        return result;

    }

    /**
     * Method used to fetch a signers certificate chain from the config
     * @return the signer certificate stored or null if no certificates have been uploaded.
     * 
     */
    @SuppressWarnings("unchecked")
    public List<Certificate> getSignerCertificateChain(final Properties config) {
        List<Certificate> result = null;
        String stringcert = (String) config.get(SIGNERCERTCHAIN);
        if (stringcert == null || stringcert.equals("")) {
            stringcert = (String) config.get(WorkerConfig.getNodeId() + "." + SIGNERCERTCHAIN);
        }

        if (stringcert != null && !stringcert.equals("")) {
            try {
                result = CertTools.getCertsFromPEM(new ByteArrayInputStream(stringcert.getBytes()));
            } catch (CertificateException | IllegalStateException e) {
                LOG.error(e);
            }
        }
        return result;
    }
}
