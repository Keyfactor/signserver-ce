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

import javax.xml.ws.Endpoint;

/**
 *
 * @author markus
 */
public class RunMock {

    public static void main(String[] args) {
        System.out.println("RunMock");

        MockEjbcaWS ejbcaWs = new MockEjbcaWS();
        Endpoint endpoint
                = Endpoint.publish("http://localhost:8111/calculator", ejbcaWs);
        
//        synchronized {
//            try {
//                new Object().wait();
//            } catch (InterruptedException ex) {
//                Logger.getLogger(RunMock.class.getName()).log(Level.SEVERE,
//                  null, ex);
//            }
//        }
    }

}
