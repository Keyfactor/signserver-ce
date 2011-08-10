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
package org.signserver.protocol.ws.client;

import java.rmi.RemoteException;
import java.rmi.ServerError;
import java.rmi.ServerException;

/**
 * A implementation of a ICommunication error that
 * could be used in most cases.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class GenericCommunicationFault implements ICommunicationFault {

    private final String description;
    private final String hostname;
    private final Throwable throwable;

    /**
     * @param description a description of what happened
     * @param hostname the host name that the client were trying to connect to.
     */
    public GenericCommunicationFault(String description, String hostname) {
        super();
        this.description = description;
        this.hostname = hostname;
        this.throwable = null;
    }

    /**
     * Default constructor 
     * @param description a description of what happened
     * @param hostname the host name that the client were trying to connect to.
     * @param throwable the error that happened during the communication
     */
    public GenericCommunicationFault(String description, String hostname, Throwable throwable) {
        super();
        this.description = description;
        this.hostname = hostname;
        this.throwable = throwable;
    }

    public GenericCommunicationFault(String hostname, Throwable _throwable) {
        this.hostname = hostname;
        if (_throwable instanceof ServerException || _throwable instanceof ServerError) {
            description = "Internal problem in server " + hostname + ". See throwed object.";
            Throwable tmp = _throwable;
            while (tmp instanceof RemoteException) {
                tmp = tmp.getCause();
            }
            this.throwable = tmp;
            return;
        }
        description = "Communication problem with " + hostname + ". See throwed object";
        this.throwable = _throwable;
    }

    public String getDescription() {
        return this.description;
    }

    public String getHostName() {
        return this.hostname;
    }

    public Throwable getThrowed() {
        return this.throwable;
    }
}
