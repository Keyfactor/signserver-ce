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
package org.signserver.common;

/**
 * Type of worker.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public enum WorkerType {
    
    /** Not yet upgraded, so any type. */
    UNKNOWN(0), // TODO: Maybe this value is not needed?

    // Note: value (1) reserved to not mix up with WorkerConfig.WORKERTYPE_ALL
    
    /** 
     * Callable by process operation (2).
     * @see WorkerConfig#WORKERTYPE_PROCESSABLE
     */
    PROCESSABLE(2),
    /**
     * Started by timed service (3). 
     * @see WorkerConfig#WORKERTYPE_SERVICES
     */
    TIMED_SERVICE(3),

    // Note: value (4) reserved for mail signer
    
    /** Not callable worker, i.e. generic config place holder or internal service/component without a more concrete type. */
    SPECIAL(10),
    /** Not callable and internal worker holding a cryptotoken. */
    CRYPTO_WORKER(11);
    
    private final int type;

    private WorkerType(int type) {
        this.type = type;
    }

    public int getType() {
        return type;
    }
    
    public static WorkerType fromType(final int type) {
        final WorkerType result;
        switch (type) {
            case 0: {
                result = UNKNOWN;
                break;
            }
            case 2: {
                result = PROCESSABLE;
                break;
            }
            case 3: {
                result = TIMED_SERVICE;
                break;
            }
            case 10: {
                result = SPECIAL;
                break;
            }
            case 11: {
                result = CRYPTO_WORKER;
                break;
            }
            default: {
                throw new IllegalArgumentException("Unsupported type: " + type);
            }
        }
        return result;
    }

}
