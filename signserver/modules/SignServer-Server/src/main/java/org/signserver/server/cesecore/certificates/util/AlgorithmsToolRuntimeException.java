/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.server.cesecore.certificates.util;

/**
 * Thrown by methods in @link {@link AlgorithmTools} when an error occurs that
 * can not be handled.
 * NOTE: THIS IS A COPY FROM org.cesecore.certificates.util
 * THIS CLASS WILL BE REMOVED WHEN UPGRADING CESECORE (DSS-2129)
 */
public class AlgorithmsToolRuntimeException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public AlgorithmsToolRuntimeException(final String message) {
        super(message);
    }

    public AlgorithmsToolRuntimeException(final String message, final Exception cause) {
        super(message, cause);
    }
}
