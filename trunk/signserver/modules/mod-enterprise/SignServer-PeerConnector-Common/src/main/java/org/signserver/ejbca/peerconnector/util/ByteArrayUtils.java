/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Helper class for interacting with ByteBuffers.
 * 
 * @version $Id$
 */
public abstract class ByteArrayUtils {

    private static final byte NEXTOBJECT_IS_NULL = 0;
    private static final byte NEXTOBJECT_IS_NOTNULL = 1;

    private static final byte BOOLEAN_FALSE = 0;
    private static final byte BOOLEAN_TRUE = 1;
    
    /** Never allow allocation of objects larger than the message maximum peer size. */
    /*  Avoid using EjbcaConfiguration.getPeerIncomingMaxMessageSize(); since this depends on the whole org.apache.commons.configuration. */
    private static final int MAX_ALLOCATION_LIMIT_BYTE_ARRAY = 134217728;
    private static final int MAX_ALLOCATION_LIMIT_LIST_ITEMS = MAX_ALLOCATION_LIMIT_BYTE_ARRAY/1024;

    /** @return a byte[] preserving the nullable property of the array */
    public static byte[] getByteArrayObjectAsBytes(final byte[] bytes) {
        if (bytes==null) {
            return ByteBuffer.allocate(1).put(NEXTOBJECT_IS_NULL).array();
        }
        return ByteBuffer.allocate(1+4+bytes.length).put(NEXTOBJECT_IS_NOTNULL).putInt(bytes.length).put(bytes).array();
    }

    /** @return a the next byte[] preserving the nullable property of the array */
    public static byte[] getNextByteArrayObject(final ByteBuffer byteBuffer) {
        if (byteBuffer.get()==NEXTOBJECT_IS_NULL) {
            return null;
        }
        final byte[] ret = new byte[assertReasonableAllocationSizeBytes(byteBuffer.getInt())];
        byteBuffer.get(ret);
        return ret;
    }

    /** @return a byte[] preserving the nullable property of the String and uses a well defined encoding. */
    public static byte[] getUtf8StringObjectAsBytes(final String value) {
        if (value==null) {
            return ByteBuffer.allocate(1).put(NEXTOBJECT_IS_NULL).array();
        }
        final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(1+4+bytes.length).put(NEXTOBJECT_IS_NOTNULL).putInt(bytes.length).put(bytes).array();
    }

    /** @return a the next String preserving the nullable property of the String and using a well defined encoding */
    public static String getNextUtf8StringObject(final ByteBuffer byteBuffer) {
        if (byteBuffer.get()==NEXTOBJECT_IS_NULL) {
            return null;
        }
        final byte[] ret = new byte[assertReasonableAllocationSizeBytes(byteBuffer.getInt())];
        byteBuffer.get(ret);
        return new String(ret, StandardCharsets.UTF_8);
    }

    /** @return a byte[] preserving the nullable property of the collections and the objects in the collections using a well defined encoding. */
    public static byte[] getUtf8StringListAsBytes(final Collection<String> collection) {
        if (collection==null) {
            return ByteBuffer.allocate(1).put(NEXTOBJECT_IS_NULL).array();
        }
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(NEXTOBJECT_IS_NOTNULL);
        try {
            baos.write(getIntAsBytes(collection.size()));
            for (final String string : collection) {
                baos.write(getUtf8StringObjectAsBytes(string));
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }
    
    /** @return the next collections and the objects in the collections using a well defined encoding. */
    public static List<String> getNextUtf8StringList(final ByteBuffer byteBuffer) {
        if (byteBuffer.get()==NEXTOBJECT_IS_NULL) {
            return null;
        }
        final int size = byteBuffer.getInt();
        final List<String> list = new ArrayList<String>(assertReasonableAllocationSizeItems(size));
        for (int i=0; i<size; i++) {
            list.add(getNextUtf8StringObject(byteBuffer));
        }
        return list;
    }

    /** @return a primitive int as bytes */
    public static byte[] getIntAsBytes(final int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }
    
    /** @return a Integer object as bytes, preserving the nullable property. */
    public static byte[] getIntegerObjectAsBytes(final Integer value) {
        if (value==null) {
            return ByteBuffer.allocate(1).put(NEXTOBJECT_IS_NULL).array();
        }
        return ByteBuffer.allocate(1+4).put(NEXTOBJECT_IS_NOTNULL).putInt(value).array();
    }

    /** @return the next Integer object, preserving the nullable property. */
    public static Integer getNextIntegerObject(final ByteBuffer byteBuffer) {
        if (byteBuffer.get()==NEXTOBJECT_IS_NULL) {
            return null;
        }
        return Integer.valueOf(byteBuffer.getInt());
    }

    /** @return a primitive long as bytes */
    public static byte[] getLongAsBytes(final long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }

    /** @return a Long object as bytes, preserving the nullable property. */
    public static byte[] getLongObjectAsBytes(final Long value) {
        if (value==null) {
            return ByteBuffer.allocate(1).put(NEXTOBJECT_IS_NULL).array();
        }
        return ByteBuffer.allocate(1+8).put(NEXTOBJECT_IS_NOTNULL).putLong(value.longValue()).array();
    }

    /** @return the next Long object, preserving the nullable property. */
    public static Long getNextLongObject(final ByteBuffer byteBuffer) {
        if (byteBuffer.get()==NEXTOBJECT_IS_NULL) {
            return null;
        }
        return Long.valueOf(byteBuffer.getLong());
    }

    /** @return a primitive boolean as a byte */
    public static byte[] getBooleanAsByte(final boolean value) {
        return ByteBuffer.allocate(1).put(value?BOOLEAN_TRUE:BOOLEAN_FALSE).array();
    }

    /** @return the next primitive boolean */
    public static boolean getNextBoolean(final ByteBuffer byteBuffer) {
        return byteBuffer.get()==BOOLEAN_TRUE;
    }

    /** Throw an IllegalStateException if the requested allocation is outside what can be considered reasonable. */
    public static int assertReasonableAllocationSizeBytes(final int suggestedAllocationSize) {
        if (suggestedAllocationSize<0 || suggestedAllocationSize>MAX_ALLOCATION_LIMIT_BYTE_ARRAY) {
            throw new IllegalStateException("Peer Message violates size limit of 0-"+MAX_ALLOCATION_LIMIT_BYTE_ARRAY+" bytes. Request was for " + suggestedAllocationSize + " bytes.");
        }
        return suggestedAllocationSize;
    }

    /** Throw an IllegalStateException if the requested allocation is outside what can be considered reasonable. */
    public static int assertReasonableAllocationSizeItems(final int suggestedAllocationSize) {
        if (suggestedAllocationSize<0 || suggestedAllocationSize>MAX_ALLOCATION_LIMIT_LIST_ITEMS) {
            throw new IllegalStateException("Peer Message violates array size limit of 0-"+(MAX_ALLOCATION_LIMIT_LIST_ITEMS)+" items. Request was for " + suggestedAllocationSize + " items.");
        }
        return suggestedAllocationSize;
    }
}
