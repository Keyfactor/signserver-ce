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
 
package org.signserver.server.annotations.wsra;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that indicates which roles the calling user must
 * have in order make the WS call. The Roles could be one
 * of the org.signserver.module.wsra.common.Roles constants
 * but are not restricted to those.
 * 
 * This annotation is mostly used to improve readability
 * of the code.
 * 
 * Important, there is no need to specify the SUPERADMIN role.
 * It have always access to all calls.
 * 
 * @author Philip Vendil 17 okt 2008
 *
 * @version $Id$
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface AuthorizedRoles {
     String[] value();
}
