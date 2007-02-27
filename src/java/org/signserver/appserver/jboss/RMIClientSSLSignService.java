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


package org.signserver.appserver.jboss;


// The JNDIMap MBean implementation
import org.signserver.rmi.ServerProperties;
import org.signserver.rmi.impl.Bind;

import se.primeKey.utils.Log4jHandler;
import se.primeKey.utils.PrimeLog;

/** A JBoss MBean that extends the JBoss ServiceMBeanSupport class. Used to create a RMI+SSL listener

*/
public class RMIClientSSLSignService extends org.jboss.system.ServiceMBeanSupport
    implements RMIClientSSLSignServiceMBean, ServerProperties, Bind.FinalizeReport {
    private Bind bind;
    private String startPortRMI;
    private String keyFileName;
    private String keyPassword;
    private String storePassword;
    private String registryPortRMI;
    private String handshakeInterval;
    private String address;
    private boolean isBinded;



    public void setStartPortRMI(String s) {
        startPortRMI = s;
    }
    public String getStartPortRMI() {
        return startPortRMI;
    }

    public void setKeyFileName(String s) {
        keyFileName = s;
    }
    public String getKeyFileName() {
        return keyFileName;
    }

    public void setKeyPassword(String s) {
        keyPassword = s;
    }
    public String getKeyPassword() {
        return keyPassword;
    }

    public void setStorePassword(String s) {
        storePassword = s;
    }
    public String getStorePassword() {
        return storePassword;
    }

    public void setRegistryPortRMI(String s){
        registryPortRMI = s;
    }
    public String getRegistryPortRMI() {
        return registryPortRMI;
    }

    /**
     * @return Returns the handshakeInterval.
     */
    public String getHandshakeInterval() {
        return handshakeInterval;
    }
    /**
     * @param handshakeInterval The handshakeInterval to set.
     */
    public void setHandshakeInterval(String handshakeInterval) {
        this.handshakeInterval = handshakeInterval;
    }
    /**
     * @return Returns the address.
     */
    public String getAddress() {
        return address;
    }
    /**
     * @param address The address to set.
     */
    public void setAddress(String a) {
        address = a;
    }
    public String getName() {
        return "RMIClientSSLJBossService";      
    }

    public synchronized void startService() throws Exception {
        super.startService();
        Log4jHandler.add();
        if ( bind==null )
            bind = new Bind( this, this );
        PrimeLog.getLogger().info("service started");
    }
    public synchronized void stopService() throws Exception {
        if ( bind!=null ) {
            isBinded = true;
            bind.unbind();
            bind = null;
            while ( isBinded ) {
                System.runFinalization();
                System.gc();
                PrimeLog.debug("waiting for Bind to finish");
                if ( isBinded )
                    wait(2000);
            }
        }
        super.stopService();
        PrimeLog.getLogger().info("service stoped");
    }
    public void bindFinalized() {
        isBinded = false;
        notifyAll();
    }
}
