/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.signserver.common.util.SecureXMLDecoder;

/**
 * Information class representing outgoing peer connections 
 * 
    INT4 id (a positive integer or -1 for "not yet assigned")
    VARCHAR(25x) name
    INT4 connectorState (0=disabled, 1=enabled)
    VARCHAR(25x) url
    CLOB data:
       reserved for future use
    INT4 rowVersion
    CLOB rowProtection
 * 
 * @version $Id$
 *
 */
public class PeerOutgoingInformation implements Serializable, Comparable<PeerOutgoingInformation> {

    public static final int PEERCONNECTOR_ID_NOT_YET_ASSIGNED = -1;
    private static final long serialVersionUID = 1L;
    private static final String KEY_AUTHENTICATION_KEYBINDING_ID = "authenticationKeyBindingId";
    private static final String KEY_LONG_HANGING_CONNECTIONS_ENABLED = "longHangingConnectionsEnabled";
    private static final String KEY_LONG_HANGING_CONNECTIONS_MIN = "longHangingConnectionsMin";
    private static final String KEY_LONG_HANGING_CONNECTIONS_MAX = "longHangingConnectionsMax";
    private int id;
    private String name;
    private PeerState state;
    private String url;
    private Integer authenticationKeyBindingId;
    private boolean longHangingConnectionsEnabled = false;
    private int longHangingConnectionsMin = 2;
    private int longHangingConnectionsMax = 2;
    
    public PeerOutgoingInformation(final int id, final String name, final PeerState state, final String url) {
        this.id = id;     
        this.name = name.trim();
        this.state = state;
        this.url = url.trim();
        this.authenticationKeyBindingId = null;
    }
    
    public PeerOutgoingInformation(final int id, final String name, final PeerState state, final String url, final String persistenceData) throws IOException {
        this.id = id;     
        this.name = name.trim();
        this.state = state;
        this.url = url.trim();
        parsePersistenceData(persistenceData);
    }

    public int getId() {
        return id;
    }

    public void setId(final int id) {
        this.id = id;
    }

    public boolean isEnabled() {
        return state.isEnabled();
    }
    
    public void setEnabled(boolean state) {
        if(state) {
            this.state = PeerState.ENABLED; 
        } else {
            this.state = PeerState.DISABLED;
        }
    }

    
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name.trim();
    }
    
    public PeerState getState() {
        return state;
    }

    public void setState(PeerState state) {
        this.state = state;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url.trim();
    }

    public Integer getAuthenticationKeyBindingId() {
        return authenticationKeyBindingId;
    }

    public void setAuthenticationKeyBindingId(final Integer authenticationKeyBindingId) {
        if (authenticationKeyBindingId!=null && authenticationKeyBindingId.intValue()==0) {
            this.authenticationKeyBindingId = null;
        } else {
            this.authenticationKeyBindingId = authenticationKeyBindingId;
        }
    }

    public boolean isLongHangingConnectionsEnabled() {
        return longHangingConnectionsEnabled;
    }
    public void setLongHangingConnectionsEnabled(final boolean longHangingConnectionsEnabled) {
        this.longHangingConnectionsEnabled = longHangingConnectionsEnabled;
    }

    public Integer getLongHangingConnectionsMin() {
        return longHangingConnectionsMin;
    }
    public void setLongHangingConnectionsMin(final Integer longHangingConnectionsMin) {
        if (longHangingConnectionsMin==null) {
            this.longHangingConnectionsMin = 2;
        } else {
            this.longHangingConnectionsMin = longHangingConnectionsMin.intValue();
            if (this.longHangingConnectionsMin<1) {
                this.longHangingConnectionsMin = 1;
            } else if (this.longHangingConnectionsMin>99) {
                this.longHangingConnectionsMin = 99;
            }
        }
    }

    public Integer getLongHangingConnectionsMax() {
        return longHangingConnectionsMax;
    }
    public void setLongHangingConnectionsMax(final Integer longHangingConnectionsMax) {
        if (longHangingConnectionsMax==null) {
            this.longHangingConnectionsMax = 50;
        } else {
            this.longHangingConnectionsMax = longHangingConnectionsMax.intValue();
            if (this.longHangingConnectionsMax<longHangingConnectionsMin) {
                this.longHangingConnectionsMax = longHangingConnectionsMin;
            } else if (this.longHangingConnectionsMax>99) {
                this.longHangingConnectionsMax = 99;
            }
        }
    }

    /**
     * When loaded from database, local non column values should be parsed in this function
     * @param persistenceData the CLOB column content
     */
    @SuppressWarnings("unchecked")
    private void parsePersistenceData(final String persistenceData) throws IOException {
        SecureXMLDecoder decoder;
        try {
            decoder = new SecureXMLDecoder(new ByteArrayInputStream(persistenceData.getBytes("UTF8")));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8  was not a supported encoding.", e);
        }
        final Map<?, ?> h = (Map<?, ?>)decoder.readObject();
        decoder.close();
        // Handle Base64 encoded string values
        final LinkedHashMap<Object, Object> dataMap = new Base64GetHashMap(h);
        // Add your local values to load here
        setAuthenticationKeyBindingId((Integer) dataMap.get(KEY_AUTHENTICATION_KEYBINDING_ID));
        setLongHangingConnectionsEnabled(Boolean.parseBoolean((String) dataMap.get(KEY_LONG_HANGING_CONNECTIONS_ENABLED)));
        setLongHangingConnectionsMin((Integer) dataMap.get(KEY_LONG_HANGING_CONNECTIONS_MIN));
        setLongHangingConnectionsMax((Integer) dataMap.get(KEY_LONG_HANGING_CONNECTIONS_MAX));
    }
    
    /**
     * When stored to the database, local non column values should be added to the CLOB in this function
     * @return a BASE64 encoded CLOB from this object's fields. 
     */
    public String constructPersistenceData() {
        try {
            // We must base64 encode string for UTF safety
            final LinkedHashMap<Object, Object> dataMap = new Base64PutHashMap();
            // Add your local values to store here
            dataMap.put(KEY_AUTHENTICATION_KEYBINDING_ID, getAuthenticationKeyBindingId());
            dataMap.put(KEY_LONG_HANGING_CONNECTIONS_ENABLED, Boolean.valueOf(isLongHangingConnectionsEnabled()).toString());
            dataMap.put(KEY_LONG_HANGING_CONNECTIONS_MIN, Integer.valueOf(getLongHangingConnectionsMin()));
            dataMap.put(KEY_LONG_HANGING_CONNECTIONS_MAX, Integer.valueOf(getLongHangingConnectionsMax()));
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final XMLEncoder encoder = new XMLEncoder(baos);
            encoder.writeObject(dataMap);
            encoder.close();
            return baos.toString("UTF8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8  was not a supported encoding.", e);
        }
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 4711). // two randomly chosen prime numbers
                append(id).
                append(name).
                append(state).
                append(url).
                toHashCode();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof PeerOutgoingInformation)) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        final PeerOutgoingInformation other = (PeerOutgoingInformation) obj;
        return new EqualsBuilder().
                append(id, other.getId()).
                append(name, other.getName()).
                append(state, other.getState()).
                append(url, other.getUrl()).
                isEquals();
    }

    @Override
    public int compareTo(PeerOutgoingInformation o) {
        return name.compareTo(o.getName());
    }
}
