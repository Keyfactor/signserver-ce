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
package org.signserver.module.xmlsigner;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Properties;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.ISignRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.server.signers.BaseSigner;
import org.apache.xml.security.Init;

/**
 * Signer outputting debug information.
 * Currently only used to output the version of the Apache Sanctuario library.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class DebugSigner extends BaseSigner {

    public static final String XMLSEC_VERSION = "xml-sec.version";
    
    @Override
    public ProcessResponse processData(ProcessRequest signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        final Properties props = new Properties();
        final ISignRequest sReq = (ISignRequest) signRequest;

        // Due to a bug in Glassfish, using getImplementationVersion isn't working...
        //props.put(XMLSEC_VERSION, Init.class.getPackage().getImplementationVersion());
    
        // get library version from Maven pom properties (workaroud for Glassfish)
        final InputStream pomPropertiesStream = Init.class
                .getResourceAsStream("/META-INF/maven/org.apache.santuario/xmlsec/pom.properties");
        try {
            final Properties pomProperties = new Properties();
            pomProperties.load(pomPropertiesStream);
            props.put(XMLSEC_VERSION, pomProperties.getProperty("version"));
        } catch (final IOException e) {
            throw new SignServerException("Failed to get xmlsec version", e);
        } finally {
            try {
                pomPropertiesStream.close();
            } catch (final IOException ignored) { //NOPMD
            }
        }

        final StringWriter writer = new StringWriter();
        props.list(new PrintWriter(writer));
        
        final GenericServletResponse resp =
                new GenericServletResponse(sReq.getRequestID(),
                        writer.getBuffer().toString().getBytes(),
                        null, null, null, null);

        return resp;
    }

}
