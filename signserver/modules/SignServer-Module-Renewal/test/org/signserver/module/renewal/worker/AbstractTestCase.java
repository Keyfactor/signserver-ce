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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Random;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession.IRemote;

/**
 * Base class for test cases. Handles creation and deletion of temporary files
 * and setup of signers etc.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class AbstractTestCase extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AbstractTestCase.class);

    private static IWorkerSession.IRemote workerSession;
    private static IGlobalConfigurationSession.IRemote globalSession;

    private Collection<File> tempFiles = new LinkedList<File>();
    private Random random = new Random();

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        SignServerUtil.installBCProvider();
        workerSession = ServiceLocator.getInstance().lookupRemote(
                IWorkerSession.IRemote.class);
        globalSession = ServiceLocator.getInstance().lookupRemote(
                IGlobalConfigurationSession.IRemote.class);
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    protected File newTempFile() {
        final String tempdir = System.getProperty("java.io.tmpdir");
        final File result = new File(tempdir, random.nextLong() + ".tmp");
        tempFiles.add(result);
        return result;
    }

    protected void removeTempFiles() {
        for (File file : tempFiles) {
            file.delete();
        }
    }

    protected static KeyStore createEmptyKeystore(final String keystoreType, 
            final String keystorePath, final String keystorePassword)
                throws KeyStoreException,
            IOException, NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException {
        final KeyStore ks;
        if ("JKS".equals(keystoreType)) {
            ks = KeyStore.getInstance(keystoreType);
        } else {
            ks = KeyStore.getInstance(keystoreType, "BC");
        }
        ks.load(null, keystorePassword.toCharArray());
        final OutputStream out = new FileOutputStream(keystorePath);
        ks.store(out, keystorePassword.toCharArray());
        out.close();
        return ks;
    }

    protected void addSigner(final int signerId, final String signerName,
            final String endEntity)
            throws IOException, KeyStoreException, NoSuchAlgorithmException,
                CertificateException, NoSuchProviderException {

        // Create keystore
        final String keystorePath = newTempFile().getAbsolutePath();
        final String keystorePassword = "foo123";
        createEmptyKeystore("PKCS12", keystorePath, keystorePassword);

        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".CLASSPATH",
            "org.signserver.module.xmlsigner.XMLSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
            "WORKER" + signerId + ".SIGNERTOKEN.CLASSPATH",
            "org.signserver.server.cryptotokens.P12CryptoToken");

        workerSession.setWorkerProperty(signerId, "NAME", signerName);
        workerSession.setWorkerProperty(signerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(signerId, "KEYSTOREPATH", keystorePath);
        workerSession.setWorkerProperty(signerId, "KEYSTOREPASSWORD",
                keystorePassword);
        if (endEntity != null) {
            getWorkerSession().setWorkerProperty(signerId, "RENEWENDENTITY",
                endEntity);
            workerSession.setWorkerProperty(signerId, "REQUESTDN",
                "CN=" + endEntity);
        }
        workerSession.setWorkerProperty(signerId, "SIGNATUREALGORITHM",
                "SHA256withRSA");
        workerSession.setWorkerProperty(signerId, "DEFAULTKEY", "key00000");
        workerSession.setWorkerProperty(signerId, "KEYSPEC", "2048");
        workerSession.setWorkerProperty(signerId, "KEYALG", "RSA");

        workerSession.reloadConfiguration(signerId);
    }

    private void removeGlobalProperties(int workerid) {
        GlobalConfiguration gc = globalSession.getGlobalConfiguration();
        Enumeration<String> en = gc.getKeyEnumeration();
        while (en.hasMoreElements()) {
            String key = en.nextElement();
            if (key.toUpperCase().startsWith("GLOB.WORKER" + workerid)) {
                key = key.substring("GLOB.".length());
                globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                        key);
            }
        }
    }

    protected void removeWorker(final int workerId) throws Exception {
        removeGlobalProperties(workerId);
        final WorkerConfig wc = workerSession.getCurrentWorkerConfig(workerId);
        final Iterator<Object> iter = wc.getProperties().keySet().iterator();
        while (iter.hasNext()) {
            final String key = (String) iter.next();
            workerSession.removeWorkerProperty(workerId, key);
        }
        workerSession.reloadConfiguration(workerId);
    }

    public IGlobalConfigurationSession getGlobalSession() {
        return globalSession;
    }

    public static IRemote getWorkerSession() {
        return workerSession;
    }

}
