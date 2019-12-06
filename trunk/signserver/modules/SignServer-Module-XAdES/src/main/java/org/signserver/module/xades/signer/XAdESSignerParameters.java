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

import org.apache.log4j.Logger;
import org.signserver.module.xades.signer.XAdESSigner.Profiles;

/**
 * Configuration values for the XAdESSigner.
 *
 * Based on patch contributed by Luis Maia &lt;lmaia@dcc.fc.up.pt&gt;.
 * 
 * @author Luis Maia <lmaia@dcc.fc.up.pt>
 * @version $Id$
 */
public class XAdESSignerParameters {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XAdESSignerParameters.class);

    private final Profiles xadesForm;
    private final TSAParameters tsaParameters;

    /**
     * Constructs an new instance of XAdESSignerParameters.
     *
     * @param xadesForm The XAdES form
     * @param tsaParameters The TSA parameters
     */
    public XAdESSignerParameters(final Profiles xadesForm, final TSAParameters tsaParameters) {
        this.xadesForm = xadesForm;
        this.tsaParameters = tsaParameters;
    }

    /**
     * Constructs an new instance of XAdESSignerParameters without TSA 
     * parameters.
     * @param xadesForm  The XAdES form
     */
    public XAdESSignerParameters(final Profiles xadesForm) {
        this(xadesForm, null);
    }

    /**
     * @return The XAdES form
     */
    public Profiles getXadesForm() {
        return xadesForm;
    }

    /**
     * @return The TSA parameters or null if no configured
     */
    public TSAParameters getTsaParameters() {
        return tsaParameters;
    }
    
    /**
     * @return True if any TSA paramaters has been configured
     */
    public boolean isTSAAvailable() {
        return tsaParameters != null;
    }

    @Override
    public String toString() {
        return "XAdESSignerParameters{" + "xadesForm=" + xadesForm + ", tsaParameters=" + tsaParameters + '}';
    }
    
}
