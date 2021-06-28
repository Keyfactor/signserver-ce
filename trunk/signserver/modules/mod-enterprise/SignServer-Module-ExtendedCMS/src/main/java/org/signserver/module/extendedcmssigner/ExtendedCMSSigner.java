/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.extendedcmssigner;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import net.jsign.DigestAlgorithm;
import net.jsign.timestamp.Timestamper;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.module.cmssigner.CMSSigner;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.utils.timestampers.RFCExternalRFC3161Timestamper;
import org.signserver.utils.timestampers.RFCInternalRFC3161Timestamper;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;

/**
 * Extended version of the CMS signer.
 * Additional feature to the basic CMSSigner is the ability to embed
 * timestamps.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ExtendedCMSSigner extends CMSSigner {
    
    // Worker properties
    public static final String TSA_URL = "TSA_URL";
    public static final String TSA_USERNAME = "TSA_USERNAME";
    public static final String TSA_PASSWORD = "TSA_PASSWORD";
    public static final String TSA_WORKER = "TSA_WORKER";
    public static final String TSA_POLICYOID = "TSA_POLICYOID";
    public static final String TSA_DIGESTALGORITHM = "TSA_DIGESTALGORITHM";

    private static final DigestAlgorithm DEFAULT_TSA_DIGESTALGORITHM =
            DigestAlgorithm.SHA256;
    
    private String tsaURL;
    private String tsaWorker;
    private String tsaUsername;
    private String tsaPassword;
    private ASN1ObjectIdentifier tsaPolicyOid;
    private DigestAlgorithm tsaDigestAlgorithm;
    
    private LinkedList<String> configErrors;

    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        // Configuration errors
        configErrors = new LinkedList<>();
        
        tsaURL = config.getProperty(TSA_URL, DEFAULT_NULL);
        tsaWorker = config.getProperty(TSA_WORKER, DEFAULT_NULL);
        tsaUsername = config.getProperty(TSA_USERNAME, DEFAULT_NULL);
        tsaPassword = config.getPropertyThatCouldBeEmpty(TSA_PASSWORD); // Might be empty string
        String value = config.getProperty(TSA_POLICYOID, DEFAULT_NULL);
        if (value == null) {
            tsaPolicyOid = null;
        } else {
            try {
                tsaPolicyOid = new ASN1ObjectIdentifier(value.trim());
            } catch (IllegalArgumentException ex) {
                configErrors.add("Incorrect value for " + TSA_POLICYOID + ": " + ex.getLocalizedMessage());
            }
        }
        
        // check that TSA_URL and TSA_WORKER is not set at the same time
        if (tsaURL != null && tsaWorker != null) {
            configErrors.add("Can not specify both " + TSA_URL + " and " + TSA_WORKER + " at the same time.");
        }
        
        final String tsaDigestAlgorithmString = config.getProperty(TSA_DIGESTALGORITHM, DEFAULT_NULL);
        if (tsaDigestAlgorithmString != null) {
            tsaDigestAlgorithm = DigestAlgorithm.of(tsaDigestAlgorithmString);
            
            if (tsaDigestAlgorithm == null) {
                configErrors.add("Illegal timestamping digest algorithm specified: " +
                                 tsaDigestAlgorithmString);
            }
        } else {
            tsaDigestAlgorithm = DEFAULT_TSA_DIGESTALGORITHM;
        }
        
        // Check that password is specified if username is
        if (tsaUsername != null && tsaPassword == null) {
            configErrors.add("Need to specify " + TSA_PASSWORD + " if " + TSA_USERNAME + " is specified.");
        }
    }
    
    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

    @Override
    protected CMSSignedData extendCMSData(CMSSignedData cms, RequestContext context) 
        throws IOException, CMSException {
        final Timestamper timestamper = createTimestamper(context);
        
        if (tsaURL != null) {
            timestamper.setURL(tsaURL);
        }

        return timestamper.timestamp(tsaDigestAlgorithm, cms);
    }

    @Override
    protected boolean extendsCMSData() {
        return tsaURL != null || tsaWorker != null;
    }
    
    /**
     * Create a timestamper instance for a request.
     * 
     * @param context Request context
     * @return A timestamper suitable for the request
     */
    protected Timestamper createTimestamper(final RequestContext context) {
        if (getTsaUrl() != null) {
            return new RFCExternalRFC3161Timestamper(tsaPolicyOid,
                                                  getTsaUsername(),
                                                  getTsaPassword());
        } else {
            return new RFCInternalRFC3161Timestamper(getTsaWorker(),
                                                  tsaPolicyOid,
                                                  getTsaUsername(),
                                                  getTsaPassword(),
                                                  getWorkerSession(context));
        }
    }
    
    protected String getTsaUrl() {
        return tsaURL;
    }
    
    protected String getTsaWorker() {
        return tsaWorker;
    }
    
    protected String getTsaUsername() {
        return tsaUsername;
    }
    
    protected String getTsaPassword() {
        return tsaPassword;
    }

    protected ASN1ObjectIdentifier getTsaPolicyOid() {
        return tsaPolicyOid;
    }

    protected InternalProcessSessionLocal getWorkerSession(final RequestContext requestContext) {
        return requestContext.getServices().get(InternalProcessSessionLocal.class);
    }
}
