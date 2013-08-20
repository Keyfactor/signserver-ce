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
package org.signserver.module.xades.signer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.server.signers.BaseSigner;
import org.apache.log4j.Logger;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.ISignRequest;
import org.signserver.common.WorkerConfig;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import xades4j.XAdES4jException;
import xades4j.production.EnvelopedXmlObject;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.production.XadesTSigningProfile;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.providers.impl.ExtendedTimeStampTokenProvider;

/**
 * A Signer using XAdES to createSigner XML documents.
 * 
 * Based on patch contributed by Luis Maia &lt;lmaia@dcc.fc.up.pt&gt;.
 * 
 * @author Luis Maia <lmaia@dcc.fc.up.pt>
 * @version $Id$
 */
public class XAdESSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XAdESSigner.class);
    
    public static final String XADESFORM = "XADESFORM";
    public static final String TSA_URL = "TSA_URL";
    public static final String TSA_USERNAME = "TSA_USERNAME";
    public static final String TSA_PASSWORD = "TSA_PASSWORD";
    
    private static final String DEFAULT_XADESFORM = "BES";
    private static final String CONTENT_TYPE = "text/xml";
    
    private LinkedList<String> configErrors;
    private XAdESSignerParameters parameters;
    
    /* XAdES profiles. */
    public enum Profiles {
        BES,
        C,
        EPES,
        T
    }

    @Override
    public void init(final int signerId, final WorkerConfig config, final WorkerContext workerContext, final EntityManager em) {
        super.init(signerId, config, workerContext, em);
        LOG.trace(">init");
        
        // Configuration errors
        configErrors = new LinkedList<String>();
        
        // XADESFORM
        Profiles form = null;
        final String xadesForm = config.getProperties().getProperty(XAdESSigner.XADESFORM, XAdESSigner.DEFAULT_XADESFORM);
        try {
            form = Profiles.valueOf(xadesForm);
        } catch (IllegalArgumentException ex) {
            configErrors.add("Incorrect value for property " + XAdESSigner.XADESFORM + ": \"" + xadesForm + "\"");
        }
        
        // TSA_URL, TSA_USERNAME, TSA_PASSWORD
        TSAParameters tsa = null;
        if (form == Profiles.T) {
            final String tsaUrl = config.getProperties().getProperty(XAdESSigner.TSA_URL);
            final String tsaUsername = config.getProperties().getProperty(XAdESSigner.TSA_USERNAME);
            final String tsaPassword = config.getProperties().getProperty(XAdESSigner.TSA_PASSWORD);
            
            if (tsaUrl == null) {
                configErrors.add("Property " + TSA_URL + " is required when " + XADESFORM + " is " + Profiles.T);
            } else {
                tsa = new TSAParameters(tsaUrl, tsaUsername, tsaPassword);
            }
        }
        
        // TODO: Configuration of signature algorithm
        // TODO: Configuration of commitment type
        // TODO: Other configuration options
        
        parameters = new XAdESSignerParameters(form, tsa);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Worker " + workerId + " configured: " + parameters);
            if (!configErrors.isEmpty()) {
                LOG.error("Worker " + workerId + " configuration error(s): " + configErrors);
            }
        }
        
        LOG.trace("<init");
    }

    @Override
    public ProcessResponse processData(ProcessRequest signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        ISignRequest sReq = (ISignRequest) signRequest;

        // Check that the request contains a valid GenericSignRequest object with a byte[].
        if (!(signRequest instanceof GenericSignRequest)) {
            throw new IllegalRequestException("Recieved request wasn't a expected GenericSignRequest.");
        }
        if (!(sReq.getRequestData() instanceof byte[])) {
            throw new IllegalRequestException("Recieved request data wasn't a expected byte[].");
        }

        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }
        
        final byte[] data = (byte[]) sReq.getRequestData();
        final String archiveId = createArchiveId(data, (String) requestContext.get(RequestContext.TRANSACTION_ID));
        final byte[] signedbytes;
        
        try {
            // Parse
            final XadesSigner signer = createSigner(parameters);
            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            final DocumentBuilder builder = factory.newDocumentBuilder();
            final Document doc = builder.parse(new ByteArrayInputStream(data));

            // Sign
            final Node node = doc.getDocumentElement();
            final SignedDataObjects dataObjs = new SignedDataObjects(new EnvelopedXmlObject(node))
                    .withCommitmentType(AllDataObjsCommitmentTypeProperty.proofOfApproval());
            signer.sign(dataObjs, doc);
            
            // Render result
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(bout));
            signedbytes = bout.toByteArray();

        } catch (SAXException ex) {
            throw new IllegalRequestException("Document parsing error", ex);
        } catch (IOException ex) {
            throw new SignServerException("Document parsing error", ex);
        } catch (ParserConfigurationException ex) {
            throw new SignServerException("Document parsing error", ex);
        } catch (XadesProfileResolutionException ex) {
            throw new SignServerException("Exception in XAdES profile resolution", ex);
        } catch (XAdES4jException ex) {
            throw new SignServerException("Exception signing document", ex);
        } catch (TransformerException ex) {
            throw new SignServerException("Transformation failure", ex);
        }
        
        // Response
        final ProcessResponse response;
        final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, signedbytes, archiveId));
        if (signRequest instanceof GenericServletRequest) {
            response = new GenericServletResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), archiveId, archivables, CONTENT_TYPE);
        } else {
            response = new GenericSignResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), archiveId, archivables);
        }
        return response;
    }

    private XadesSigner createSigner(final XAdESSignerParameters params) throws SignServerException, XadesProfileResolutionException, CryptoTokenOfflineException {
        final KeyingDataProvider kdp = new DirectKeyingDataProvider((X509Certificate) this.getSigningCertificate(), this.getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN));
        final XadesSigningProfile xsp;
        switch (params.getXadesForm()) {
            case BES:
                xsp = new XadesBesSigningProfile(kdp);
                break;
            case T:
                xsp = new XadesTSigningProfile(kdp)
                        .withTimeStampTokenProvider(ExtendedTimeStampTokenProvider.class)
                        .withBinding(TSAParameters.class, params.getTsaParameters());
                break;
            case C:
            case EPES:
            default:
                throw new SignServerException("Unsupported XAdES profile configured");
        }
        return (XadesSigner) xsp.newSigner();
    }

    @Override
    protected List<String> getFatalErrors() {
        final LinkedList<String> errors = new LinkedList<String>(super.getFatalErrors());
        errors.addAll(configErrors);
        return errors;
    }

    public XAdESSignerParameters getParameters() {
        return parameters;
    }

}
