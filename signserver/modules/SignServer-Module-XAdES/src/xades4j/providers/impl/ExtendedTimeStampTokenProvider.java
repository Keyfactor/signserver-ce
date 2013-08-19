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
package xades4j.providers.impl;

import com.google.inject.Inject;
import java.io.IOException;
import java.net.HttpURLConnection;
import xades4j.providers.MessageDigestEngineProvider;
import org.signserver.module.xades.signer.TSAParameters;
import xades4j.utils.Base64;

/**
 * TimeStampTokenProvider with added support for HTTP Basic Authentication.
 * 
 * TODO: Contribute this back to XAdES4j.
 *
 * @author Luis Maia <lmaia@dcc.fc.up.pt>
 */
public final class ExtendedTimeStampTokenProvider extends DefaultTimeStampTokenProvider {

    private final String base64tsaUsrAndPwd;

    @Inject
    public ExtendedTimeStampTokenProvider(final MessageDigestEngineProvider mdep, final TSAParameters tsaParameters) {
        super(mdep, tsaParameters.getUrl());
        final String user = tsaParameters.getUsername();
        if (user == null) {
            base64tsaUsrAndPwd = null;
        } else {
            final String usrAndPwd = user + ":" + tsaParameters.getPassword();
            this.base64tsaUsrAndPwd = Base64.encodeBytes(usrAndPwd.getBytes());
        }
    }

    @Override
    HttpURLConnection getHttpConnection() throws IOException {
        final HttpURLConnection connection = super.getHttpConnection();
        if (this.base64tsaUsrAndPwd != null) {
            connection.setRequestProperty("Authorization", "Basic " + this.base64tsaUsrAndPwd);
        }
        return connection;
    }
}
