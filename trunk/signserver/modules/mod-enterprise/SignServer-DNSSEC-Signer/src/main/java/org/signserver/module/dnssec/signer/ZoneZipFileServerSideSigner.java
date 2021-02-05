/** ***********************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 ************************************************************************ */
package org.signserver.module.dnssec.signer;

import org.signserver.module.dnssec.common.ZoneFileParser;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.util.List;
import java.util.Locale;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.ReadableData;
import org.signserver.module.dnssec.common.ZoneHelper;
import org.signserver.server.WorkerContext;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.module.dnssec.common.ZoneClientHelper.Phase1Data;
import org.signserver.module.dnssec.common.ZoneSignatureCreator;

/**
 * DNSSEC ZoneZip File server-side signer.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class ZoneZipFileServerSideSigner extends BaseZoneFileServerSideSigner {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(ZoneZipFileServerSideSigner.class);

    private static final String REQUEST_CONTENT_TYPE = "application/zip";  
       
    // Request metadata property constants    
    private static final String METADATA_FORCE_RESIGN = "FORCE_RESIGN";      

    private static final String PROPERTY_MIN_REMAINING_VALIDITY = "MIN_REMAINING_VALIDITY";     
    
    private Long minRemainingValidity;

    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM); 
        
        String minRemainingValidityValue = config.getProperty(PROPERTY_MIN_REMAINING_VALIDITY, DEFAULT_NULL);
        if (minRemainingValidityValue != null) {
            try {
                // MIN_REMAINING_VALIDITY specified in seconds
                // Convert it into milliseconds
                minRemainingValidity = (Long.valueOf(minRemainingValidityValue)) * 1000;
            } catch (NumberFormatException ex) {
                configErrors.add("Invalid value for " + PROPERTY_MIN_REMAINING_VALIDITY);
            }
        }
    }
    
    private static boolean getForceResign(final RequestContext context)
            throws IllegalRequestException {
        final String forceResign =
                RequestMetadata.getInstance(context).get(METADATA_FORCE_RESIGN);

        if (forceResign != null) {
            switch (forceResign.toLowerCase(Locale.ENGLISH)) {
                case "true":
                    return true;
                case "false":
                    return false;
                default:
                    throw new IllegalRequestException("Illegal value for FORCE_RESIGN: " +
                                                      forceResign);
            }
        } else {
            return false;
        }
    }
    
    @Override
    protected ZoneFileParser extractZoneFileAndParse(ReadableData requestData, RequestContext requestContext, String zoneName, List<InputStream> inputStreamsToBeClosed) throws IOException, IllegalRequestException {
        return ZoneHelper.createParserFromZoneZip(requestData.getAsFile(), zoneName, getForceResign(requestContext), inputStreamsToBeClosed);
    }

    @Override
    protected ZoneSignatureCreator createSignatureCreator(final Phase1Data d,
                                                          final KeyPair zsk1KeyPair)
        throws IllegalRequestException {        

        return new ZipZoneFileServerSideSignatureCreator(d, zsk1KeyPair,
                                                         minRemainingValidity);
    }

    @Override
    protected String getRequestContentType() {
        return REQUEST_CONTENT_TYPE;
    }

}
