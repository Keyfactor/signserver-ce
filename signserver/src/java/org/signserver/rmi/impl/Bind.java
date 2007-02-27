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

 
package org.signserver.rmi.impl;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Security;
import java.util.Properties;

import javax.net.ssl.TrustManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.signserver.rmi.ServerProperties;

import se.primeKey.SetApplicationInfo;
import se.primeKey.utils.PrimeLog;
import se.primeKey.utils.PrimeProperties;
import se.primeKey.utils.RMIPort;

public class Bind extends se.primeKey.utils.BindRMIObject {
    
    static final String objectNameInRegistry = "SignServer";

    final private ServerProperties sProps;

    public Bind(ServerProperties p, FinalizeReport r) throws Exception {
        super(r, p.getAddress());
        sProps = p;
    }

    private static class MyServerProperties implements ServerProperties {
        final private Properties properties;
        MyServerProperties() throws FileNotFoundException, IOException {
            properties = new PrimeProperties(this);
        }



        /* (non-Javadoc)
         * @see se.primeKey.rmi.ServerProperties#getStartPortRMI()
         */
        public String getStartPortRMI() {
            return properties.getProperty("startPortRMI");
        }

        /* (non-Javadoc)
         * @see se.primeKey.rmi.ServerProperties#getRegistryPortRMI()
         */
        public String getRegistryPortRMI() {
            return properties.getProperty("registryPortRMI");
        }

        /* (non-Javadoc)
         * @see se.primeKey.rmi.ServerProperties#getKeyFileName()
         */
        public String getKeyFileName() {
            return properties.getProperty("keyFileName");
        }

        /* (non-Javadoc)
         * @see se.primeKey.rmi.ServerProperties#getKeyPassword()
         */
        public String getKeyPassword() {
            return properties.getProperty("keyPassword");
        }

        /* (non-Javadoc)
         * @see se.primeKey.rmi.ServerProperties#getStorePassword()
         */
        public String getStorePassword() {
            return properties.getProperty("storePassword");
        }

        /* (non-Javadoc)
         * @see se.primeKey.rmi.ServerProperties#getHandshakeInterval()
         */
        public String getHandshakeInterval() {
            return properties.getProperty("handshakeInterval");
        }



        /* (non-Javadoc)
         * @see org.signserver.rmi.ServerProperties#getAddress()
         */
        public String getAddress() {
            return properties.getProperty("address");
        }

    }
    public static void main(String args[]) {
        Security.addProvider( new BouncyCastleProvider() );
        SetApplicationInfo.doIt();
        try {
            new Bind( new MyServerProperties(), null );
        } catch (Exception e) {
            PrimeLog.throwing(e);
            PrimeLog.debug("Trouble: " + e);
        }
    }

    protected String getKeyFileName() {
        return sProps.getKeyFileName();
    }

    protected String getStorePassword() {
        return sProps.getStorePassword();
    }

    protected String getKeyPassword() {
        return sProps.getKeyPassword();
    }

    protected TrustManager[] getTrustManagers() {
        return null;
    }

    protected String getStartPortRMI() {
        return sProps.getStartPortRMI();
    }

    protected String getHandshakeInterval() {
        return sProps.getHandshakeInterval();
    }

    protected Remote getServerImpl(RMIPort p) throws RemoteException {
        return new ServerImpl(p);
    }

    protected String getRegistryPortRMI() {
        return sProps.getRegistryPortRMI();
    }

    protected String getObjectNameInRegistry() {
        return "SignServer";
    }


}
