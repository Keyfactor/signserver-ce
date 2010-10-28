/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.signserver.module.renewal.worker;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.ws.Endpoint;

/**
 *
 * @author markus
 */
public class RunMock {

    public static void main(String[] args) {
        System.out.println("RunMock");

        MockEjbcaWS ejbcaWs = new MockEjbcaWS();
        Endpoint endpoint = Endpoint.publish("http://localhost:8111/calculator", ejbcaWs);
        
//        synchronized {
//            try {
//                new Object().wait();
//            } catch (InterruptedException ex) {
//                Logger.getLogger(RunMock.class.getName()).log(Level.SEVERE, null, ex);
//            }
//        }
    }

}
