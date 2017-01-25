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
package org.signserver.module.tsa;

import java.io.IOException;
import javax.persistence.EntityManager;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.WorkerContext;

/**
 * Extended time stamp signer supporting additional extensions.
 * Currently supports the Qualified statement extension
 * http://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf
 * 
 * @author Marcus Lundblad
 * @version $Id: ExtendedTimeStampSigner.java 7214 2016-04-19 07:28:18Z malu9369 $
 */
public class ExtendedTimeStampSigner extends TimeStampSigner {

    final static ASN1ObjectIdentifier ID_ETSI_TSTS;
    final static String INCLUDE_QC_EXTENSION = "INCLUDE_QC_EXTENSION";
    private boolean includeQCExtension;
    
    static {
        ID_ETSI_TSTS = new ASN1ObjectIdentifier("0.4.0.19422.1.1");
    }
    
    @Override
    public void init(final int signerId, final WorkerConfig config,
                     final WorkerContext workerContext,
                     final EntityManager workerEntityManager) {
        super.init(signerId, config, workerContext, workerEntityManager);
        
        final String includeQCExtensionString =
                config.getProperty(INCLUDE_QC_EXTENSION);

        if (includeQCExtensionString == null || includeQCExtensionString.trim().isEmpty()) {
            includeQCExtension = false;
        } else if (Boolean.TRUE.toString().equals(includeQCExtensionString.trim())) {
            includeQCExtension = true;
        } else if (Boolean.FALSE.toString().equals(includeQCExtensionString.trim())) {
            includeQCExtension = false;
        } else {
            configErrors.add("Incorrect value for property " + INCLUDE_QC_EXTENSION);
        }
    }

    /**
     * Get additional extension fullfilling EU regulation 910/2014 for
     * qualified timestamps.
     * 
     * http://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf
     * 
     * ASN 1 structure specification:
     * 
     * -- object identifiers
     * id-etsi-tsts                OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0) 
     *                                                     id-tst-profile(19422) 1 }
     * id-etsi-tsts-EuQCompliance  OBJECT IDENTIFIER ::= { id-etsi-tsts 1 } 
     * -- statements 
     * esi4-qtstStatement-1 QC-STATEMENT ::= { IDENTIFIED BY id-etsi-tsts-EuQCompliance }
     * 
     * @param request Process request
     * @param context Request context
     * @return An Extensions instance containing the QC extension, as specified
     *         if the extension has been configured for inclusion, otherwise
     *         null
     * @throws IOException 
     */
    @Override
    protected Extensions getAdditionalExtensions(final Request request,
                                                 final RequestContext context)
        throws IOException {
        if (includeQCExtension) {
            final Extension ext =
                    new Extension(Extension.qCStatements, false,
                                  new DERSequence(new QCStatement(ID_ETSI_TSTS)).getEncoded());
            return new Extensions(ext);
        } else {
            return null;
        }
    }
}
