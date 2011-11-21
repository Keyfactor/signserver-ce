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
package org.signserver.module.pdfsigner;

import com.lowagie.text.pdf.PdfWriter;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;

/**
 * Class representing the permissions settings of a PDF and the properties in 
 * SignServer to configure them.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Permissions {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(Permissions.class);
    
    private static final Map<String, Integer> permissionStringToInt = new HashMap<String, Integer>();
    private static final Map<Integer, String> permissionIntToString = new HashMap<Integer, String>();
    
    public static final String ALLOW_PRINTING = "ALLOW_PRINTING";
    public static final String ALLOW_MODIFY_CONTENTS = "ALLOW_MODIFY_CONTENTS";
    public static final String ALLOW_COPY = "ALLOW_COPY";
    public static final String ALLOW_MODIFY_ANNOTATIONS = "ALLOW_MODIFY_ANNOTATIONS";
    public static final String ALLOW_FILL_IN = "ALLOW_FILL_IN";
    public static final String ALLOW_SCREENREADERS = "ALLOW_SCREENREADERS";
    public static final String ALLOW_ASSEMBLY = "ALLOW_ASSEMBLY";
    public static final String ALLOW_DEGRADED_PRINTING = "ALLOW_DEGRADED_PRINTING";
    
    static {
        permissionStringToInt.put(ALLOW_ASSEMBLY, PdfWriter.ALLOW_ASSEMBLY);
        permissionStringToInt.put(ALLOW_COPY, PdfWriter.ALLOW_COPY);
        permissionStringToInt.put(ALLOW_DEGRADED_PRINTING, PdfWriter.ALLOW_DEGRADED_PRINTING);
        permissionStringToInt.put(ALLOW_FILL_IN, PdfWriter.ALLOW_FILL_IN);
        permissionStringToInt.put(ALLOW_MODIFY_ANNOTATIONS, PdfWriter.ALLOW_MODIFY_ANNOTATIONS);
        permissionStringToInt.put(ALLOW_MODIFY_CONTENTS, PdfWriter.ALLOW_MODIFY_CONTENTS);
        permissionStringToInt.put(ALLOW_PRINTING, PdfWriter.ALLOW_PRINTING);
        permissionStringToInt.put(ALLOW_SCREENREADERS, PdfWriter.ALLOW_SCREENREADERS);
        
        permissionIntToString.put(PdfWriter.ALLOW_ASSEMBLY, ALLOW_ASSEMBLY);
        permissionIntToString.put(PdfWriter.ALLOW_COPY, ALLOW_COPY);
        permissionIntToString.put(PdfWriter.ALLOW_DEGRADED_PRINTING, ALLOW_DEGRADED_PRINTING);
        permissionIntToString.put(PdfWriter.ALLOW_FILL_IN, ALLOW_FILL_IN);
        permissionIntToString.put(PdfWriter.ALLOW_MODIFY_ANNOTATIONS, ALLOW_MODIFY_ANNOTATIONS);
        permissionIntToString.put(PdfWriter.ALLOW_MODIFY_CONTENTS, ALLOW_MODIFY_CONTENTS);
        permissionIntToString.put(PdfWriter.ALLOW_PRINTING, ALLOW_PRINTING);
        permissionIntToString.put(PdfWriter.ALLOW_SCREENREADERS, ALLOW_SCREENREADERS);
    }
    
    private int permissions;

    private Permissions(int permissions) {
        this.permissions = permissions;
    }

    public static Permissions fromInt(int permissions) {
        return new Permissions(permissions);
    }
    public static Permissions fromSet(Collection<String> permissions) {
        return new Permissions(toPermissionsBits(permissions));
    }
    
    public static Permissions fromSet(Collection<String> permissions, boolean failOnUnknown) throws UnknownPermissionException {
        return new Permissions(toPermissionsBits(permissions, failOnUnknown));
    }
    
    private static int toPermissionsBits(Collection<String> permissionsSet) {
        int result = 0;
        if (permissionsSet != null) {
            for (String permission: permissionsSet) {
                Integer permissionInt = permissionStringToInt.get(permission);
                if (permissionInt == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Unknown permission specified: \"" + permission + "\"");
                    }
                } else {
                    result += permissionInt;
                }
            }
        }
        return result;
    }
    
    private static int toPermissionsBits(Collection<String> permissionsSet, boolean failOnUnknown) throws UnknownPermissionException {
        int result = 0;
        if (permissionsSet != null) {
            for (String permission: permissionsSet) {
                Integer permissionInt = permissionStringToInt.get(permission);
                if (permissionInt == null) {
                    if (failOnUnknown) {
                        throw new UnknownPermissionException(permission);
                    }
                } else {
                    result += permissionInt;
                }
            }
        }
        return result;
    }
    
    private static Set<String> toPermissionsSet(int permissionBits) {
        Set<String> result = new HashSet<String>();
        for (Map.Entry<Integer, String> perm : permissionIntToString.entrySet()) {
            if ((permissionBits & perm.getKey()) != 0) {
                result.add(perm.getValue());
            }
        }
        return result;
    }
    
    public Set<String> asSet() {
        return toPermissionsSet(permissions);
    }

    public int asInt() {
        return permissions;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Permissions other = (Permissions) obj;
        if (this.permissions != other.permissions) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 37 * hash + this.permissions;
        return hash;
    }
    

    @Override
    public String toString() {
        return new StringBuilder().append("Permissions(").append(permissions).append(")").append(asSet()).toString();
    }
    
    public boolean containsAnyOf(Permissions others) {
        // If permissions contains any of the others the result
        // of permissions BITWISEAND others will be non-zero
        return (permissions & others.permissions) != 0;
    }

}
