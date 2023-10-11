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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import org.bouncycastle.util.encoders.Hex;

/**
 * Public and private attributes for different key types.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AttributeProperties {

    private static final String ATTRIBUTE = "ATTRIBUTE";
    private static final String ATTRIBUTE_DOT = ATTRIBUTE + ".";
    private static final String OBJECT_PUBLIC = "PUBLIC";
    private static final String OBJECT_PRIVATE = "PRIVATE";

    private final Map<String, List<Attribute>> publicTemplateMap;
    private final Map<String, List<Attribute>> privateTemplateMap;
    
    /**
     * Parses the attributes from worker properties.
     * Properties not prefixed with "ATTRIBUTE." are ignored.
     * @param properties to read attributes from
     * @return the parsed attribute properties
     * @throws IllegalArgumentException in case of incorrectly formatted attribute property name or value
     */
    public static AttributeProperties fromWorkerProperties(Properties properties) throws IllegalArgumentException {
        final Map<String, List<Attribute>> publicTemplateMap = new HashMap<>();
        final Map<String, List<Attribute>> privateTemplateMap = new HashMap<>();
        
        for (String attributeObjectKeyAttribute : properties.stringPropertyNames()) {
            attributeObjectKeyAttribute = attributeObjectKeyAttribute.trim();
            
            if (attributeObjectKeyAttribute.startsWith(ATTRIBUTE_DOT)) {
                final String objectKeyAttribute = attributeObjectKeyAttribute.substring(ATTRIBUTE_DOT.length());
                int nextDot = objectKeyAttribute.indexOf(".");
                if (nextDot == -1 || objectKeyAttribute.length() < nextDot + 1) {
                    throw new IllegalArgumentException("Incorrect attribute property name: " + attributeObjectKeyAttribute);
                } else {
                    final String object = objectKeyAttribute.substring(0, nextDot);
                    final String keyAttribute = objectKeyAttribute.substring(object.length() + 1);
                    nextDot = keyAttribute.indexOf(".");
                    if (nextDot == -1 || keyAttribute.length() < nextDot + 1) {
                        throw new IllegalArgumentException("Incorrect attribute property name: " + attributeObjectKeyAttribute);
                    } else {
                        final String keyType = keyAttribute.substring(0, nextDot).toUpperCase(Locale.ENGLISH);
                        
                        List<Attribute> publicTemplate = publicTemplateMap.get(keyType);
                        if (publicTemplate == null) {
                            publicTemplate = new ArrayList<>();
                            publicTemplateMap.put(keyType, publicTemplate);
                        }

                        List<Attribute> privateTemplate = privateTemplateMap.get(keyType);
                        if (privateTemplate == null) {
                            privateTemplate = new ArrayList<>();
                            privateTemplateMap.put(keyType, privateTemplate);
                        }

                        final String attribute = keyAttribute.substring(keyType.length() + 1);
                        final long attributeId;
                        if (attribute.startsWith("0x") || attribute.startsWith("0X")) {
                            attributeId = Long.parseLong(attribute.substring("0x".length()), 16);
                        } else if (attribute.startsWith("CKA_")) {
                            Long id = AttributeNames.longFromName(attribute.substring("CKA_".length()));
                            if (id == null) {
                                throw new IllegalArgumentException("Incorrect attribute property name: " + attributeObjectKeyAttribute + ". Unknown attribute: " + attribute);
                            }
                            attributeId = id;
                        } else {
                            attributeId = Long.parseLong(attribute);
                        }
                        final String value = properties.getProperty(attributeObjectKeyAttribute);
                        final Attribute attributeObject = new Attribute(attributeId, getObjectValue(attribute, value));
                        
                        switch (object) {
                            case OBJECT_PUBLIC:
                                publicTemplate.add(attributeObject);
                                break;
                            case OBJECT_PRIVATE:
                                privateTemplate.add(attributeObject);
                                break;
                            default:
                                // Ignore unknown object type
                        }
                    }
                }
            }
        }

        return new AttributeProperties(publicTemplateMap, privateTemplateMap);
    }

    private static Object getObjectValue(String attribute, String value) throws IllegalArgumentException {
        Object result;
        switch (attribute) {
            case "CKA_ALLOWED_MECHANISMS":
                result = AllowedMechanisms.parse(value).toBinaryEncoding();
                break;
            default:
                if ("TRUE".equalsIgnoreCase(value)) {
                    result = true;
                } else if ("FALSE".equalsIgnoreCase(value)) {
                    result = false;
                } else {
                    throw new IllegalArgumentException("Not a boolean value: " + value);
                }
        }
        return result;
    }
    
    private static String getStringValue(String attribute, Object value) throws IllegalArgumentException {
        String result;
        if (value instanceof byte[]) {
            if (attribute.equals("CKA_ALLOWED_MECHANISMS")) {
                result = AllowedMechanisms.fromBinaryEncoding((byte[]) value).toPropertyValue();
            } else {
                result = Hex.toHexString((byte[]) value);
            }
        } else {
            result = String.valueOf(value);
        }
        return result;
    }

    /**
     * Constructs an instance of AttributeProperties with the given template maps.
     *
     * @param publicTemplate templates for public objects
     * @param privateTemplate templates for private objects
     */
    public AttributeProperties(Map<String, List<Attribute>> publicTemplate, Map<String, List<Attribute>> privateTemplate) {
        this.publicTemplateMap = publicTemplate;
        this.privateTemplateMap = privateTemplate;
    }

    /**
     * Get the list of public attributes for the supplied key type.
     * @param keyType to get the attributes for
     * @return list of attributes
     */
    public List<Attribute> getPublicTemplate(final String keyType) {
        return publicTemplateMap.get(keyType.toUpperCase(Locale.ENGLISH));
    }

    /**
     * Get the list of private attributes for the supplied key type.
     * @param keyType to get the attributes for
     * @return list of attributes
     */
    public List<Attribute> getPrivateTemplate(final String keyType) {
        return privateTemplateMap.get(keyType.toUpperCase(Locale.ENGLISH));
    }        

    /**
     * @return Properties representation of the templates
     */
    public Properties toWorkerProperties() {
        Properties properties = new Properties();
        fill(properties, OBJECT_PRIVATE, privateTemplateMap);
        fill(properties, OBJECT_PUBLIC, publicTemplateMap);
        return properties;
    }
    
    @Override
    public String toString() {
        StringWriter sw = new StringWriter();
        toWorkerProperties().list(new PrintWriter(sw));
        return sw.toString();
    }

    private void fill(Properties properties, String object, Map<String, List<Attribute>> templateMap) {
        for (Map.Entry<String, List<Attribute>> entry : templateMap.entrySet()) {
            for (Attribute attribute : entry.getValue()) {
                String name = AttributeNames.nameFromLong(attribute.getId());
                if (name == null) {
                    name = String.valueOf(attribute.getId());
                }
                name = "CKA_" + name;
                properties.setProperty(ATTRIBUTE_DOT + object + "." + entry.getKey() + "." + name, getStringValue(name, attribute.getValue()));
            }
        }
    }

    /**
     * Holder for an attribute.
     */
    public static class Attribute implements Comparable<Attribute> {

        private final long id;
        private final Object value;

        public Attribute(long id, Object value) {
            this.id = id;
            this.value = value;
        }

        public long getId() {
            return id;
        }

        public Object getValue() {
            return value;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 53 * hash + (int) (this.id ^ (this.id >>> 32));
            hash = 53 * hash + Objects.hashCode(this.value);
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
            final Attribute other = (Attribute) obj;
            if (this.id != other.id) {
                return false;
            }
            if (!Objects.equals(this.value, other.value)) {
                return false;
            }
            return true;
        }
        
        @Override
        public int compareTo(Attribute o) {
            return toString().compareTo(o.toString());
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder();
            sb.append("Attribute ")
                    .append(AttributeNames.nameFromLong(id))
                    .append("(")
                    .append(String.format("0x%08x", id))
                    .append(")")
                    .append("=");
            if (value instanceof byte[]) {
                sb.append(Hex.toHexString((byte[]) value));
            } else {
                sb.append(value);
            }
            return sb.toString();
        }

    }
}
