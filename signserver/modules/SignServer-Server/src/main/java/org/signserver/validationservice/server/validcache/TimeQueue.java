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
package org.signserver.validationservice.server.validcache;

import java.security.cert.Certificate;
import java.util.Date;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;


/**
 * TimeQueue is an internal class to the validation cache data structure.
 * Keeping count on how long a validation should exist in cache.
 *  
 * 
 * @author Philip Vendil 26 nov 2007
 *
 * @version $Id$
 */
class TimeQueue {

    private Queue<TimeCertPair> timeQueue = new ConcurrentLinkedQueue<TimeCertPair>();
    private ValidationMap validationMap;
    private long cacheTimeMS;

    /**
     * Main constructor for a time queue
     * 
     * @param validationMap a reference to the validation map.
     * @param cacheTimeMS time in milliseconds that the certificate should be cached.
     */
    TimeQueue(ValidationMap validationMap, long cacheTimeMS) {
        this.validationMap = validationMap;
        this.cacheTimeMS = cacheTimeMS;
    }

    /**
     * Method used to remove all expired validations from the ValidationMap and
     * from the end queue
     */
    void popOld() {
        Date currentDate = new Date();

        while (true) {
            TimeCertPair timeCertPair = timeQueue.peek();
            if (timeCertPair != null && timeCertPair.getDate().before(currentDate)) {
                timeQueue.remove();
                validationMap.remove(timeCertPair.getCert());
            } else {
                break;
            }
        }
    }

    /**
     * Inserts a new certificate to the beginning queue
     */
    void pushNew(Certificate cert) {
        timeQueue.add(new TimeCertPair(new Date(System.currentTimeMillis() + cacheTimeMS), cert));
    }

    /**
     * Simple VO containing a time and certificate that was inserted
     * into the queue. 
     * 
     */
    private class TimeCertPair {

        private Date date;
        private Certificate cert;

        TimeCertPair(Date date, Certificate cert) {
            this.date = date;
            this.cert = cert;
        }

        /**
         * @return the date
         */
        public Date getDate() {
            return date;
        }

        /**
         * @return the cert
         */
        public Certificate getCert() {
            return cert;
        }
    }
}
