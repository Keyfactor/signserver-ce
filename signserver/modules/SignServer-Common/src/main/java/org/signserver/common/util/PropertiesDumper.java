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

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;
import org.ejbca.util.Base64;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;
import static org.signserver.common.util.PropertiesConstants.*;

/**
 * TODO.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class PropertiesDumper {
    
    public static void dumpNonWorkerSpecificGlobalConfiguration(Properties gc, Properties outProps) {
        for (String key : gc.stringPropertyNames()) {
            if (!key.startsWith(GLOBAL_PREFIX) || !key.startsWith(WORKER_PREFIX, GLOBAL_PREFIX.length())) {
                outProps.setProperty(key, gc.getProperty(key));
            }
        }
    }
    
    public static void dumpWorkerProperties(int workerId, GlobalConfiguration gc, WorkerConfig workerConfig, Properties outProps) throws CertificateEncodingException {
        dumpWorkerProperties(workerId, gc.getConfig(), workerConfig.getProperties(), outProps);
    }
    
    public static void dumpWorkerProperties(int workerId, Properties gc, Properties workerConfig, Properties outProps) throws CertificateEncodingException {
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
        WorkerConfig wc = new WorkerConfig();
        wc.getProperties().putAll(workerConfig); // XXX: More ugly then usual...
        ProcessableConfig pConfig = new ProcessableConfig(wc);
        if (pConfig.getSignerCertificate() != null) {
            X509Certificate cert = pConfig.getSignerCertificate();
            outProps.setProperty("WORKER" + workerId + SIGNERCERTIFICATE, new String(Base64.encode(cert.getEncoded(), false)));
        }
        if (pConfig.getSignerCertificateChain() != null) {
            Collection<Certificate> certs = pConfig.getSignerCertificateChain();
            Iterator<Certificate> iter2 = certs.iterator();
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

            outProps.setProperty("WORKER" + workerId + SIGNERCERTCHAIN, chainValue);
        }

        if (pConfig.getAuthorizedClients().size() > 0) {
            Collection<AuthorizedClient> aClients = pConfig.getAuthorizedClients();
            int i = 1;
            for (AuthorizedClient client : aClients) {
                outProps.setProperty("WORKER" + workerId + AUTHCLIENT + i, client.getCertSN() + ";" + client.getIssuerDN());
                i++;
            }
        }
    }
    
}
