/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.msauthcode.signer;

import java.util.ArrayList;
import java.util.List;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcSpOpusInfo;
import net.jsign.asn1.authenticode.SpcStatementType;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.Attribute;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;

/**
 * Utility methods used by MSAuthCode-based signers.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MSAuthCodeUtils {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeUtils.class);
    
    /**
     * Create authenticated attributes for an Authenticode signature based
     * on request data and authenticode options.
     * 
     * @param requestContext Request context (can override the program name
     *                                        and program URL values, if allowed)
     * @param authCodeOptions Configuration options for Authenticode, determines
     *                        default values and if overriding via the request
     *                        context is allowed for each option
     * @return Authenticated attributes
     * @throws IllegalRequestException if the request tries to override a parameter
     *                                 that is specifically not allowed to be
     *                                 overridden
     */
    public static AttributeTable createAuthenticatedAttributes(final RequestContext requestContext,
                                                               final MSAuthCodeOptions authCodeOptions)
        throws IllegalRequestException {
        List<Attribute> attributes = new ArrayList<>();
        
        SpcStatementType spcStatementType = new SpcStatementType(AuthenticodeObjectIdentifiers.SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID);
        attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_STATEMENT_TYPE_OBJID, new DERSet(spcStatementType)));
        
        String programNameToUse = authCodeOptions.getProgramName();
        String programURLToUse = authCodeOptions.getProgramURL();
        final String requestedName = RequestMetadata.getInstance(requestContext).get(MSAuthCodeOptions.PROGRAM_NAME);
        final String requestedURL = RequestMetadata.getInstance(requestContext).get(MSAuthCodeOptions.PROGRAM_URL);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Configured programName: " + programNameToUse + ", configured programURL: " + programURLToUse
                    + "\nRequested programName: " + requestedName + ", requested programURL: " + requestedURL);
        }

        if (requestedName != null) {
            if (authCodeOptions.isAllowProgramNameOverride()) {
                if (requestedName.trim().isEmpty()) { // Treat empty as removal of name
                    programNameToUse = null;
                } else {
                    programNameToUse = requestedName;
                }
            } else {
                throw new IllegalRequestException("Requesting PROGRAM_NAME not allowed.");
            }
        }

        if (requestedURL != null) {
            if (authCodeOptions.isAllowProgramURLOverride()) {
                if (requestedURL.trim().isEmpty()) { // Treat empty as removal of name
                    programURLToUse = null;
                } else {
                    programURLToUse = requestedURL;
                }
            } else {
                throw new IllegalRequestException("Requesting PROGRAM_URL not allowed.");
            }
        }

        SpcSpOpusInfo spcSpOpusInfo =
                new SpcSpOpusInfo(programNameToUse, programURLToUse);
        attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_SP_OPUS_INFO_OBJID, new DERSet(spcSpOpusInfo)));
        
        return new AttributeTable(new DERSet(attributes.toArray(new ASN1Encodable[attributes.size()])));
    } 
}
