
package org.signserver.common;

/**
 * Exception thrown when a runtime implementation doesn't support a given operation.
 * F.ex. used when trying to import signing certificates to a crypto token
 * not supporting this, like a soft crypto token.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class OperationUnsupportedException extends Exception {
    public OperationUnsupportedException(final String message) {
        super(message);
    }
}
