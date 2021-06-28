/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.dnssec.signer;

import org.signserver.module.dnssec.common.ZoneFileParser;
import java.io.InputStream;
import org.signserver.common.data.ReadableData;
import java.io.IOException;
import java.security.KeyPair;
import java.util.List;
import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.module.dnssec.common.ZoneClientHelper;
import org.signserver.module.dnssec.common.ZoneHelper;
import org.signserver.module.dnssec.common.ZoneSignatureCreator;

/**
 * DNSSEC Zone File server-side signer.
 *
 * @author Marcus Lundblad
 * @author Vinay Singh
 * @author Markus Kilås
 * @version $Id$
 */
public class ZoneFileServerSideSigner extends BaseZoneFileServerSideSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ZoneFileServerSideSigner.class);

    private static final String REQUEST_CONTENT_TYPE = "text/plain";   
                       
    @Override
    protected ZoneFileParser extractZoneFileAndParse(ReadableData requestData, RequestContext requestContext, String zoneName, List<InputStream> inputStreamsToBeClosed) throws IOException {
        InputStream inputStream = requestData.getAsInputStream();
        inputStreamsToBeClosed.add(inputStream);
        return ZoneHelper.createParserFromZone(inputStream, zoneName);
    }

    @Override
    protected String getRequestContentType() {
        return REQUEST_CONTENT_TYPE;
    }

    @Override
    protected ZoneSignatureCreator createSignatureCreator(ZoneClientHelper.Phase1Data d, KeyPair zsk1KeyPair) {
        return new ZoneFileServerSideSignatureCreator(d, zsk1KeyPair);
    }

}
