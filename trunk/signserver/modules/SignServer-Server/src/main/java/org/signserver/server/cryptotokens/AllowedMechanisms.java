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
package org.signserver.server.cryptotokens;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.LongBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Representation of a list of allowed mechanisms.
 *
 * Implements parsing and encoding of the values.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AllowedMechanisms {
    
    private final List<Long> mechs;

    public AllowedMechanisms(List<Long> mechs) {
        this.mechs = mechs;
    }

    /**
     * Parses the allowed mechanisms from the property value.
     *
     * @param allowedMechanismsProperty to parse
     * @return the parsed instance
     * @throws IllegalArgumentException in case of some of the values can not be parsed
     */
    public static AllowedMechanisms parse(final String allowedMechanismsProperty) throws IllegalArgumentException {
        final String[] parts = allowedMechanismsProperty.split("[,;\\s]");
        final List<Long> mechs = new ArrayList<>(parts.length);
        for (String part : parts) {
            part = part.trim();
            if (!part.isEmpty()) {
                // Parse as hexadecimal or decimal number
                try {
                    if (part.startsWith("0x") && part.length() > 2) {
                        mechs.add(Long.parseLong(part.substring(2), 16));
                    } else {
                        if (part.startsWith("CKM_")) {
                            part = part.substring("CKM_".length());
                        }
                        Long l = MechanismNames.longFromName(part);
                        if (l == null) {
                            l = Long.parseLong(part);
                        }
                        mechs.add(l);
                    }
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException("Mechanism could not be parsed as number: " + ex.getMessage());
                }
            }
        }
        return new AllowedMechanisms(mechs);
    }
    
    public static AllowedMechanisms fromBinaryEncoding(final byte[] binary) throws IllegalArgumentException {
        final ArrayList<Long> mechs = new ArrayList<>();
        try {
            final LongBuffer lb = ByteBuffer.wrap(binary).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer();
            while (lb.hasRemaining()) {
                mechs.add(lb.get());
            }
        } catch (BufferUnderflowException ex) {
            throw new IllegalArgumentException("Unable to parse allowed mechanisms value: " + ex.getMessage());
        }
        return new AllowedMechanisms(mechs);
    }

    /**
     * @return the allowed mechanisms in the encoding expected by PKCS#11 for the CKA_ALLOWED_MECHANISMS attribute
     */
    public byte[] toBinaryEncoding() {
        final int num = mechs.size();
        final ByteBuffer bb = ByteBuffer.allocate(8 * num);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        for (long mech : mechs) {
            bb.putLong(mech);
        }
        return bb.array();
    }

    /**
     * @return the allowed mechanisms as an array with the values
     */
    public Long[] toLongArray() {
        return mechs.toArray(new Long[0]);
    }

    /**
     * @return the allowed mechanisms encoded as a string property
     */
    public String toPropertyValue() {
        final StringBuilder sb = new StringBuilder();
        final Iterator<Long> iterator = mechs.iterator();
        while (iterator.hasNext()) {
            sb.append(MechanismNames.nameFromLong(iterator.next()));
            //sb.append(String.format("0x%08x", iterator.next()));
            if (iterator.hasNext()) {
                sb.append(", ");
            }
        }
        return sb.toString();
    }

    /**
     * @return String representation (i.e. for debugging)
     * @see #toPropertyValue() 
     */
    @Override
    public String toString() {
        return "AllowedMechanisms{" + toPropertyValue() + "}";
    }

}
