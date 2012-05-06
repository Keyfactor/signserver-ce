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
package org.signserver.server.entities;

import java.io.Serializable;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import org.apache.log4j.Logger;

/**
 * Counter in database for number of signings made with a particular key.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@Entity
@Table(name = "KeyUsageCounter")
public class KeyUsageCounter implements Serializable {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(KeyUsageCounter.class);

    @Id
    private String keyHash;

    private long counter;

    public KeyUsageCounter() {
        counter = 0;
    }

    public KeyUsageCounter(String keyHash) {
        this();
        this.keyHash = keyHash;
    }

    public long getCounter() {
        return counter;
    }

    public String getKeyHash() {
        return keyHash;
    }

    @Override
    public String toString() {
        return "Counter(" + keyHash +", " + counter + ")";
    } 

}
