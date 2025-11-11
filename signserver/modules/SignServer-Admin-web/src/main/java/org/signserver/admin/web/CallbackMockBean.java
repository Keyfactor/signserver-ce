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

package org.signserver.admin.web;

import jakarta.enterprise.inject.Alternative;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Alternative implementation when OIDC is not enabled.
 */
@Alternative
public class CallbackMockBean implements CallbackInterface {
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

    }
}
