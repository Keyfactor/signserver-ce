/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.utils.timestampers.TimestampHelper;


/**
 * TSPSource impementation using an external TSA with added support for
 * HTTP basic authorization.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ExternalTSPSource implements TSPSource {
    private final URL tsaURL;
    private final String basicAuthorization;
    
    public ExternalTSPSource(final String tsaURL,
                             final String username,
                             final String password)
            throws MalformedURLException {
        this.tsaURL = new URL(tsaURL);
        if (username == null) {
            basicAuthorization = null;
        } else {
            final String usrAndPwd = username + ":" + password;
            basicAuthorization = Base64.toBase64String(usrAndPwd.getBytes());
        }
    }

    @Override
    public TimestampBinary getTimeStampResponse(final DigestAlgorithm da,
                                                final byte[] digest)
        throws DSSException {
        final TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(true);

        try {
            final TimeStampRequest req =
                reqGen.generate(new ASN1ObjectIdentifier(da.getOid()),
                                digest);
            byte[] request = req.getEncoded();

            final CMSSignedData cms =
                    TimestampHelper.responseToRFCTimestamp(TimestampHelper.fetchTimestampExternal(request,
                tsaURL, basicAuthorization, "application/timestamp-query",
                "application/timestamp-reply"),
                                      req);

            return new TimestampBinary(cms.getEncoded());
        } catch (IOException | CMSException | TSPException ex) {
            throw new DSSException("Failed to timestamp", ex);
        }
    }
}
