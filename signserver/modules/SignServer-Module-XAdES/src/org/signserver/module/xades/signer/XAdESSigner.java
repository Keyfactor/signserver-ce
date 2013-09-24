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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
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
import xades4j.providers.TimeStampTokenProvider;
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
    
    /** Worker property: XADESFORM. */
    public static final String PROPERTY_XADESFORM = "XADESFORM";
    
    /** Worker property: TSA_URL. */
    public static final String PROPERTY_TSA_URL = "TSA_URL";
    
    /** Worker property: TSA_USERNAME. */
    public static final String PROPERTY_TSA_USERNAME = "TSA_USERNAME";
    
    /** Worker property: TSA_PASSWORD. */
    public static final String PROPERTY_TSA_PASSWORD = "TSA_PASSWORD";
    
    /** Worker property: COMMITMENT_TYPES. */
    public static final String PROPERTY_COMMITMENT_TYPES = "COMMITMENT_TYPES";
    
    /** Default value use if the worker property XADESFORM has not been set. */
    private static final String DEFAULT_XADESFORM = "BES";

    private static final String CONTENT_TYPE = "text/xml";
    
    private LinkedList<String> configErrors;
    private XAdESSignerParameters parameters;
    
    private Collection<AllDataObjsCommitmentTypeProperty> commitmentTypes;
    
    private Class<? extends TimeStampTokenProvider> timeStampTokenProviderImplementation =
            ExtendedTimeStampTokenProvider.class;
    
    /** 
     * Electronic signature forms defined in ETSI TS 101 903 V1.4.1 (2009-06)
     * section 4.4.
     */
    public enum Profiles {
        BES,
        C,
        EPES,
        T
    }
    
    
    /**
     * Commitment types defined in ETSI TS 101 903 V1.4.1 (2009-06).
     * section 7.2.6.
     */
    public enum CommitmentTypes {
        PROOF_OF_APPROVAL(AllDataObjsCommitmentTypeProperty.proofOfApproval()),
        PROOF_OF_CREATION(AllDataObjsCommitmentTypeProperty.proofOfCreation()),
        PROOF_OF_DELIVERY(AllDataObjsCommitmentTypeProperty.proofOfDelivery()),
        PROOF_OF_ORIGIN(AllDataObjsCommitmentTypeProperty.proofOfOrigin()),
        PROOF_OF_RECEIPT(AllDataObjsCommitmentTypeProperty.proofOfReceipt()),
        PROOF_OF_SENDER(AllDataObjsCommitmentTypeProperty.proofOfSender());
        
        CommitmentTypes(AllDataObjsCommitmentTypeProperty commitmentType) {
            prop = commitmentType;
        }
        
        AllDataObjsCommitmentTypeProperty getProp() {
            return prop;
        }
        
        AllDataObjsCommitmentTypeProperty prop;
    }

    @Override
    public void init(final int signerId, final WorkerConfig config, final WorkerContext workerContext, final EntityManager em) {
        super.init(signerId, config, workerContext, em);
        LOG.trace(">init");
        
        // Configuration errors
        configErrors = new LinkedList<String>();
        
        // PROPERTY_XADESFORM
        Profiles form = null;
        final String xadesForm = config.getProperties().getProperty(PROPERTY_XADESFORM, XAdESSigner.DEFAULT_XADESFORM);
        try {
            form = Profiles.valueOf(xadesForm);
        } catch (IllegalArgumentException ex) {
            configErrors.add("Incorrect value for property " + PROPERTY_XADESFORM + ": \"" + xadesForm + "\"");
        }
        
        // PROPERTY_TSA_URL, PROPERTY_TSA_USERNAME, PROPERTY_TSA_PASSWORD
        TSAParameters tsa = null;
        if (form == Profiles.T) {
            final String tsaUrl = config.getProperties().getProperty(PROPERTY_TSA_URL);
            final String tsaUsername = config.getProperties().getProperty(PROPERTY_TSA_USERNAME);
            final String tsaPassword = config.getProperties().getProperty(PROPERTY_TSA_PASSWORD);
            
            if (tsaUrl == null) {
                configErrors.add("Property " + PROPERTY_TSA_URL + " is required when " + PROPERTY_XADESFORM + " is " + Profiles.T);
            } else {
                tsa = new TSAParameters(tsaUrl, tsaUsername, tsaPassword);
            }
        }
        
        // TODO: Configuration of signature algorithm
        // TODO: Other configuration options
        
        final String commitmentTypesProperty = config.getProperties().getProperty(PROPERTY_COMMITMENT_TYPES);
        
        if (commitmentTypesProperty == null) {
            commitmentTypes = Collections.singletonList(AllDataObjsCommitmentTypeProperty.proofOfApproval());
        } else {
            commitmentTypes = new LinkedList<AllDataObjsCommitmentTypeProperty>();

            // an empty value for COMMITMENT_TYPE means not including any commitment type properties
            if (!"".equals(commitmentTypesProperty)) {
                for (final String part : commitmentTypesProperty.split(",")) {
                    final String type = part.trim();

                    try {
                        commitmentTypes.add(CommitmentTypes.valueOf(type).getProp());
                    } catch (IllegalArgumentException e) {
                        configErrors.add("Unkown commitment type: " + type);
                    }
                }
            }
        }

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

        // Check that the request contains a valid GenericSignRequest object with a byte[].
        if (!(signRequest instanceof GenericSignRequest)) {
            throw new IllegalRequestException("Recieved request wasn't a expected GenericSignRequest.");
        }
        
        final ISignRequest sReq = (ISignRequest) signRequest;
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
            SignedDataObjects dataObjs = new SignedDataObjects(new EnvelopedXmlObject(node));
            
            for (final AllDataObjsCommitmentTypeProperty commitmentType : commitmentTypes) {
                    dataObjs = dataObjs.withCommitmentType(commitmentType);
            }
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

    /**
     * Creates the signer implementation given the parameters.
     *
     * @param params Parameters such as XAdES form and TSA properties.
     * @return The signer implementation
     * @throws SignServerException In case an unsupported XAdES form was specified
     * @throws XadesProfileResolutionException if the dependencies of the signer cannot be resolved
     * @throws CryptoTokenOfflineException If the private key is not available
     */
    private XadesSigner createSigner(final XAdESSignerParameters params) throws SignServerException, XadesProfileResolutionException, CryptoTokenOfflineException {
        // Setup key and certificiates
        final List<X509Certificate> xchain = new LinkedList<X509Certificate>();
        for (Certificate cert : this.getSigningCertificateChain()) {
            if (cert instanceof X509Certificate) {
                xchain.add((X509Certificate) cert);
            }
        }
        final KeyingDataProvider kdp = new CertificateAndChainKeyingDataProvider(xchain, this.getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN));
        
        // Signing profile
        final XadesSigningProfile xsp;
        switch (params.getXadesForm()) {
            case BES:
                xsp = new XadesBesSigningProfile(kdp);
                break;
            case T:
                xsp = new XadesTSigningProfile(kdp)
                        .withTimeStampTokenProvider(timeStampTokenProviderImplementation)
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
    
    /**
     * Internal method used for the unit test to override the time stamp token provider.
     * 
     * @param implementation
     */
    void setTimeStampTokenProviderImplementation(final Class<? extends TimeStampTokenProvider> implementation) {
        timeStampTokenProviderImplementation = implementation;
    }

}
