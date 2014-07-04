/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
 * Abstract Status class containing token status.
 *
 * @deprecated This class is only kept for backwards compatibility. Use
 * WorkerStatus instead.
 *
 * @author Philip Vendil 23 nov 2007
 * @version $Id$
 */
@Deprecated
public abstract class CryptoTokenStatus extends WorkerStatus {}
