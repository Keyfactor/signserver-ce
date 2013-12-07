package org.signserver.server.annotations;

/**
 * Enumeration of supported Transaction types by the cluster
 * class loader. Supports means that no new transaction will 
 * be created and Required means that a new transaction will
 * be created.
 * 
 * @author Philip Vendil 23 okt 2008
 * @version $Id$
 */
public enum TransactionType {

    SUPPORTS,
    REQUIRED
}
