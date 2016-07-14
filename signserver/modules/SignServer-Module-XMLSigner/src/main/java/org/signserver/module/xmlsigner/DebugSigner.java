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
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.apache.xalan.Version;
import org.apache.xalan.processor.TransformerFactoryImpl;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.server.signers.BaseSigner;
import org.apache.xml.security.Init;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;

/**
 * Signer outputting debug information.
 * Currently only used to output the version of the Apache Sanctuario library
 * and other.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class DebugSigner extends BaseSigner {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DebugSigner.class);

    public static final String XMLSEC_VERSION = "xml-sec.version";
    public static final String XALAN_VERSION = "xalan.version";
    public static final String SIGNSERVER_NODEID_VALUE = "signserver_nodeid.value";
    
    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        final Properties props = new Properties();
        final SignatureRequest sReq = (SignatureRequest) signRequest;
        final WritableData responseData = sReq.getResponseData();

        // Due to a bug in Glassfish, using getImplementationVersion isn't working...
        //props.put(XMLSEC_VERSION, Init.class.getPackage().getImplementationVersion());
        //props.put(XALAN_VERSION, TransformerFactoryImpl.class.getPackage().getImplementationVersion());
    
        // get library version from Maven pom properties (workaroud for Glassfish)
        try {
            props.put(XMLSEC_VERSION, getPropertiesFromResource(Init.class, "/META-INF/maven/org.apache.santuario/xmlsec/pom.properties").getProperty("version"));
        } catch (final IOException e) {
            throw new SignServerException("Failed to get xmlsec version", e);
        }

        String xalanVersion = Version.getVersion();
        if (xalanVersion == null) {
            xalanVersion = TransformerFactoryImpl.class.getPackage().getImplementationVersion();        
            if (xalanVersion == null) {
                try {
                    xalanVersion = getVersionFromFilename(TransformerFactoryImpl.class, "xalan");
                } catch (final IOException e) {
                    throw new SignServerException("Failed to get xalan version", e);
                }
            }
        }
        props.put(XALAN_VERSION, xalanVersion == null ? "0.0" : xalanVersion);

        // Add the SIGNSERVER_NODEID environment variable
        String nodeId = System.getenv("SIGNSERVER_NODEID");
        props.put(SIGNSERVER_NODEID_VALUE, nodeId == null ? "(null)" : nodeId);
        
        try (PrintWriter out = new PrintWriter(responseData.getAsOutputStream())) {
            props.list(out);
        } catch (IOException ex) {
            throw new SignServerException("IO error", ex);
        }
        
        final SignatureResponse resp =
                new SignatureResponse(sReq.getRequestID(),
                        responseData,
                        null, null, null, null);
        return resp;
    }
    
    /**
     * Get a properties file identified by resource from the same place as the
     * specified class.
     * @param clazz To get the resource from
     * @param resource name of the Properties file
     * @return The loaded properties file
     * @throws IOException In case the Properties file could not be read
     */
    private Properties getPropertiesFromResource(Class clazz, String resource) throws IOException {
        // get library version from Maven pom properties (workaroud for Glassfish)
        final InputStream pomPropertiesStream = clazz
                .getResourceAsStream(resource);
        try {
            final Properties pomProperties = new Properties();
            pomProperties.load(pomPropertiesStream);
            return pomProperties;
        } finally {
            try {
                pomPropertiesStream.close();
            } catch (final IOException ignored) { //NOPMD
            }
        }
    }
    
    /**
     * Try to obtain the version of the JAR based on the file name of the JAR,
     * if available from the class loader.
     * @param clazz In the JAR to get the version from
     * @param fileTitle Name of the library 
     * @return The version from the file name if available or "0.0"
     * @throws IOException In case the location of the file could not be
     * obtained.
     */
    private String getVersionFromFilename(Class clazz, String fileTitle) throws IOException {
        if (clazz.getProtectionDomain() != null) {
            if (clazz.getProtectionDomain().getCodeSource() != null) {
                final String url = clazz.getProtectionDomain().getCodeSource().getLocation().toExternalForm();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Got URL: " + url);
                }
                Pattern pattern = Pattern.compile(".*" + fileTitle + "-(.*).jar");
                Matcher matcher = pattern.matcher(url);
                if (matcher.matches()) {
                    return matcher.group(1);
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("No " + fileTitle + "- in URL");
                    }
                }
            } else {
                LOG.debug("Code source is null");
            }
        } else {
            LOG.debug("Protection domain is null");
        }
        return null;
    }

}
