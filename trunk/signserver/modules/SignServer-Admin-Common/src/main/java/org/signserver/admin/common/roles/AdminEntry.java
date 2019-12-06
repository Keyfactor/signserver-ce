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
package org.signserver.admin.common.roles;

import java.util.Objects;
import org.signserver.common.ClientEntry;

/**
 * Entry containing the authorized roles for the administrator identified by the
 * certificate serial number and issuer.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AdminEntry {
    
    private final ClientEntry client;
    private boolean admin;
    private boolean auditor;
    private boolean archiveAuditor;
    private boolean peerSystem;
    private final String hexSerialNumber;

    public AdminEntry(final ClientEntry client, final boolean admin, final boolean auditor, final boolean archiveAuditor, final boolean peerSystem) {
        this.client = client;
        this.admin = admin;
        this.auditor = auditor;
        this.archiveAuditor = archiveAuditor;
        this.peerSystem = peerSystem;
        this.hexSerialNumber = client.getSerialNumber().toString(16);
    }

    public AdminEntry(final ClientEntry client) {
        this.client = client;
        this.hexSerialNumber = client.getSerialNumber().toString(16);
    }

    public ClientEntry getClient() {
        return client;
    }

    public boolean isAdmin() {
        return admin;
    }

    public boolean isAuditor() {
        return auditor;
    }

    public boolean isArchiveAuditor() {
        return archiveAuditor;
    }

    public boolean isPeerSystem() {
        return peerSystem;
    }

    public void setAdmin(boolean admin) {
        this.admin = admin;
    }

    public void setAuditor(boolean auditor) {
        this.auditor = auditor;
    }

    public void setArchiveAuditor(boolean archiveAuditor) {
        this.archiveAuditor = archiveAuditor;
    }

    public void setPeerSystem(boolean peerSystem) {
        this.peerSystem = peerSystem;
    }

    public String getHexSerialNumber() {
        return hexSerialNumber;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 41 * hash + Objects.hashCode(this.client);
        hash = 41 * hash + (this.admin ? 1 : 0);
        hash = 41 * hash + (this.auditor ? 1 : 0);
        hash = 41 * hash + (this.archiveAuditor ? 1 : 0);
        hash = 41 * hash + (this.peerSystem ? 1 : 0);
        hash = 41 * hash + Objects.hashCode(this.hexSerialNumber);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AdminEntry other = (AdminEntry) obj;
        if (this.admin != other.admin) {
            return false;
        }
        if (this.auditor != other.auditor) {
            return false;
        }
        if (this.archiveAuditor != other.archiveAuditor) {
            return false;
        }
        if (this.peerSystem != other.peerSystem) {
            return false;
        }
        if (!Objects.equals(this.hexSerialNumber, other.hexSerialNumber)) {
            return false;
        }
        if (!Objects.equals(this.client, other.client)) {
            return false;
        }
        return true;
    }

    public String getRoles() {
        final StringBuilder sb = new StringBuilder();
        if (admin) {
            sb.append("Admin");
        }
        if (auditor) {
            if (sb.length() != 0) {
                sb.append(", ");
            }
            sb.append("Auditor");
        }
        if (archiveAuditor) {
            if (sb.length() != 0) {
                sb.append(", ");
            }
            sb.append("Archive Auditor");
        }
        if (peerSystem) {
            if (sb.length() != 0) {
                sb.append(", ");
            }
            sb.append("Peer System");
        }
        return sb.toString();
    }
    
}
