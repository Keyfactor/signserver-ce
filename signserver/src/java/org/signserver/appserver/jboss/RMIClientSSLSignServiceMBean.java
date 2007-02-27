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

// The JNDIMap MBean interface

/** An example MBean that extends the JBoss ServiceMBeanSupport class.
This is version 2 as shown in Listing 2.8.
*/
public interface RMIClientSSLSignServiceMBean extends org.jboss.system.ServiceMBean {

    void setStartPortRMI(String s);
    String getStartPortRMI();

    void setKeyFileName(String s);
    String getKeyFileName();

    void setKeyPassword(String s);
    String getKeyPassword();

    void setStorePassword(String s);
    String getStorePassword();

    void setRegistryPortRMI(String s);
    String getRegistryPortRMI();

    void setHandshakeInterval(String handshakeInterval);
    String getHandshakeInterval(); 
    
    void setAddress(String a);
    String getAddress();

}
