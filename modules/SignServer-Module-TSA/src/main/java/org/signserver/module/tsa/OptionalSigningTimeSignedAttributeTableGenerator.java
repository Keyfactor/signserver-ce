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

import java.util.Map;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;

/**
 * Implementation of a signed CMS attibute table generator with
 * the ability to exclude the signingTime attribute.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class OptionalSigningTimeSignedAttributeTableGenerator extends
        DefaultSignedAttributeTableGenerator {
    
    private boolean includeSigningTime;

    /**
     *
     * @param includeSigningTime Determines whether to include the signingTime attribute
     */
    public OptionalSigningTimeSignedAttributeTableGenerator(final boolean includeSigningTime) {
        this.includeSigningTime = includeSigningTime;
    }

    @Override
    public AttributeTable getAttributes(Map parameters) {
        final AttributeTable attrs = super.getAttributes(parameters);
        
        if (!includeSigningTime) {
            return attrs.remove(CMSAttributes.signingTime);
        }
        
        return attrs;
    }
}
