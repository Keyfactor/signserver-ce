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
package org.signserver.module.cmssigner;

import java.util.Collection;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;

/**
 * Implementation of a signed CMS attribute table generator with
 * the ability to exclude a collection of attributes.
 *
 * @author Marcus Lundblad
 * @author Markus Kilås
 * @version $Id: FilteredSignedAttributeTableGenerator.java 12770 2021-06-15 06:24:37Z malu9369 $
 *
 */
public class FilteredSignedAttributeTableGenerator extends
        DefaultSignedAttributeTableGenerator {
    
    private final Collection<ASN1ObjectIdentifier> attributesToRemove;

    /**
     *
     * @param attributesToRemove Collection of attributes to not include
     */
    public FilteredSignedAttributeTableGenerator(final Collection<ASN1ObjectIdentifier> attributesToRemove) {
        this.attributesToRemove = attributesToRemove;
    }

    public FilteredSignedAttributeTableGenerator(final Collection<ASN1ObjectIdentifier> attributesToRemove,
                                                 final AttributeTable at) {
        super(at);
        this.attributesToRemove = attributesToRemove;
    }

    @Override
    public AttributeTable getAttributes(Map parameters) {
        AttributeTable attrs = super.getAttributes(parameters);

        for (ASN1ObjectIdentifier oid : attributesToRemove) {
            attrs = attrs.remove(oid);
        }

        return attrs;
    }
}
