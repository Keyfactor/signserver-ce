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
package org.signserver.common.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;
import static org.signserver.common.util.PropertiesConstants.*;

/**
 * Utility methods for dumping (exporting) global and worker configuration.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PropertiesDumper {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(PropertiesDumper.class);
    
    /**
     * Only dumps properties not related to a worker.
     * @param gc the global configuration properties
     * @param outProps to write the properties to
     */
    public static void dumpNonWorkerSpecificGlobalConfiguration(Properties gc, Properties outProps) {
        for (String key : gc.stringPropertyNames()) {
            if (!key.startsWith(GLOBAL_PREFIX_DOT) || !key.startsWith(WORKER_PREFIX, GLOBAL_PREFIX_DOT.length())) {
                outProps.setProperty(key, gc.getProperty(key));
            }
        }
    }
    
    /**
     * Extracts a worker's global and worker properties.
     * @param workerId Id of worker to get the properties from
     * @param gc the global configuration
     * @param workerConfig the worker configuration
     * @param outProps to write the properties to
     * @throws CertificateEncodingException in case of certificate encoding errors
     */
    public static void dumpWorkerProperties(int workerId, GlobalConfiguration gc, WorkerConfig workerConfig, Properties outProps) throws CertificateEncodingException {
        ProcessableConfig pConfig = new ProcessableConfig(workerConfig);
        dumpWorkerProperties(workerId, gc.getConfig(), workerConfig.getProperties(), pConfig.getAuthorizedClients(), outProps);
    }
    
    /**
     * Extracts a worker's global and worker properties.
     * @param workerId Id of worker to get the properties from
     * @param gc the global configuration properties
     * @param workerConfig the worker configuration properties
     * @param authorizedClients
     * @param outProps to write the properties to
     * @throws CertificateEncodingException in case of certificate encoding errors
     */
    public static void dumpWorkerProperties(final int workerId, final Properties gc, final Properties workerConfig, final Collection<AuthorizedClient> authorizedClients, final Properties outProps) throws CertificateEncodingException {
        Enumeration<String> en = (Enumeration<String>) gc.propertyNames();
        while (en.hasMoreElements()) {
            String next = en.nextElement();
            if (next.substring(5).startsWith("WORKER" + workerId)) {
                outProps.put(next, gc.getProperty(next));
            }
        }

        for (String key : workerConfig.stringPropertyNames()) {
            outProps.setProperty("WORKER" + workerId + "." + key, workerConfig.getProperty(key));
        }

        // Also dump Authorized Clients and/or signer certificates
        X509Certificate signerCertificate = getSignerCertificate(workerConfig);
        if (signerCertificate != null) {
            outProps.setProperty("WORKER" + workerId + DOT_SIGNERCERTIFICATE, new String(Base64.encode(signerCertificate.getEncoded(), false)));
        }
        List<Certificate> signerCertificateChain = getSignerCertificateChain(workerConfig);
        if (signerCertificateChain != null) {
            Iterator<Certificate> iter2 = signerCertificateChain.iterator();
            String chainValue = "";
            while (iter2.hasNext()) {
                Certificate cert = iter2.next();
                String certData = new String(Base64.encode(cert.getEncoded(), false));
                if (chainValue.equals("")) {
                    chainValue = certData;
                } else {
                    chainValue += ";" + certData;
                }
            }

            outProps.setProperty("WORKER" + workerId + DOT_SIGNERCERTCHAIN, chainValue);
        }

        if (authorizedClients.size() > 0) {
            int i = 1;
            for (AuthorizedClient client : authorizedClients) {
                outProps.setProperty("WORKER" + workerId + DOT_AUTHCLIENT + i, client.getCertSN() + ";" + client.getIssuerDN());
                i++;
            }
        }
    }
    
    private static X509Certificate getSignerCertificate(final Properties conf) {
        X509Certificate result = null;
        String stringcert = conf.getProperty(SIGNERCERT);

        if (stringcert != null && !stringcert.equals("")) {
            Collection<?> certs;
            try {
                certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(stringcert.getBytes()));
                if (certs.size() > 0) {
                    result = (X509Certificate) certs.iterator().next();
                }
            } catch (CertificateException e) {
                LOG.error(e);
            } catch (IOException e) {
                LOG.error(e);
            }
        }
        return result;
    }
    
    private static List<Certificate> getSignerCertificateChain(final Properties conf) {
        List<Certificate> result = null;
        String stringcert = conf.getProperty(SIGNERCERTCHAIN);

        if (stringcert != null && !stringcert.equals("")) {
            try {
                result = CertTools.getCertsFromPEM(new ByteArrayInputStream(stringcert.getBytes()));
            } catch (CertificateException e) {
                LOG.error(e);
            } catch (IOException e) {
                LOG.error(e);
            }
        }
        return result;
    }
}
