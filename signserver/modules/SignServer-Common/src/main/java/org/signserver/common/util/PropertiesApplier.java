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
package org.signserver.common.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.signserver.common.AuthorizedClient;

/**
 * Base class implementing applying a previous parsed configuration property batch.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public abstract class PropertiesApplier {

    public static final String WORKER_PREFIX = "WORKER";
    public static final String OLDWORKER_PREFIX = "SIGNER";
    public static final String GENID = "GENID";
    
    protected static class PropertiesApplierException extends Exception {
        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        public PropertiesApplierException(final String message) {
            super(message);
        }
    }
    
    /**
     * Holds the map of generated worker IDs.
     */
    private HashMap<String, Integer> genIds = new HashMap<String, Integer>();
    
    /**
     * Hold the worker IDs updated-
     */
    private Set<Integer> workerIds = new HashSet<Integer>();
    
    /**
     * Apply configuration prepared by the configuration parser.
     * Should call the parse method on a parser instance to use with this method.
     * 
     * @param parser
     */
    public void apply(final PropertiesParser parser) {       
        try {
            final Map<PropertiesParser.GlobalProperty, String> setGlobalProperties =
                    translateGlobalProperties(parser.getSetGlobalProperties());
            final List<PropertiesParser.GlobalProperty> removeGlobalProperties =
                    translateGlobalProperties(parser.getRemoveGlobalProperties());
            final Map<PropertiesParser.WorkerProperty, String> setWorkerProperties =
                    translateWorkerProperties(parser.getSetWorkerProperties());
            final List<PropertiesParser.WorkerProperty> removeWorkerProperties =
                    translateWorkerProperties(parser.getRemoveWorkerProperties());
            final Map<Integer, byte[]> signerCertificates =
                    translateWorkerDatas(parser.getSignerCertificates());
            final Map<Integer, List<byte[]>> signerCertificateChains =
                    translateWorkerDatas(parser.getSignerCertificateChains());
            final Map<Integer, List<AuthorizedClient>> addAuthorizedClients =
                    translateWorkerDatas(parser.getAddAuthorizedClients());
            final Map<Integer, List<AuthorizedClient>> removeAuthorizedClients =
                    translateWorkerDatas(parser.getRemoveAuthorizedClients());
         
            for (final PropertiesParser.GlobalProperty prop : setGlobalProperties.keySet()) {
                setGlobalProperty(prop.getScope(), prop.getKey(), setGlobalProperties.get(prop));
            }
            
            for (final PropertiesParser.GlobalProperty prop : removeGlobalProperties) {
                removeGlobalProperty(prop.getScope(), prop.getKey());
            }
            
            for (final PropertiesParser.WorkerProperty prop : setWorkerProperties.keySet()) {
                setWorkerProperty(Integer.parseInt(prop.getWorkerIdOrName()), prop.getKey(), setWorkerProperties.get(prop));
            }
            
            for (final PropertiesParser.WorkerProperty prop : removeWorkerProperties) {
                removeWorkerProperty(Integer.parseInt(prop.getWorkerIdOrName()), prop.getKey());
            }
            
            for (final int workerId : signerCertificates.keySet()) {
                uploadSignerCertificate(workerId, signerCertificates.get(workerId));
            }
            
            for (final int workerId : signerCertificateChains.keySet()) {
                uploadSignerCertificateChain(workerId, signerCertificateChains.get(workerId));
            }
            
            for (final int workerId : addAuthorizedClients.keySet()) {
                for (final AuthorizedClient ac : addAuthorizedClients.get(workerId)) {
                    addAuthorizedClient(workerId, ac);
                }
            }
            
            for (final int workerId : removeAuthorizedClients.keySet()) {
                for (final AuthorizedClient ac : removeAuthorizedClients.get(workerId)) {
                    removeAuthorizedClient(workerId, ac);
                }
            }
            
        } catch (PropertiesApplierException e) {
            // TODO: report errro
        }
        
    }
    
    /**
     * Translate global property map.
     * Will take care of translating generated worker IDs and convert worker names to worker IDs for global property keys.
     * 
     * @param properties Map containing a mapping from global property identifiers to property values
     * @return Resulting mapping
     * @throws PropertiesApplierException
     */
    private Map<PropertiesParser.GlobalProperty, String> translateGlobalProperties(
            final Map<PropertiesParser.GlobalProperty, String> properties)
            throws PropertiesApplierException {
        final Map<PropertiesParser.GlobalProperty, String> result =
                new HashMap<PropertiesParser.GlobalProperty, String>();
        
        for (final PropertiesParser.GlobalProperty prop : properties.keySet()) {
            result.put(new PropertiesParser.GlobalProperty(prop.getScope(),
                                                           translateGlobalPropertyKey(prop.getKey())),
                                                           properties.get(prop));
        }
        
        return result;
    }
    
    /**
     * Translate a list of global properties.
     * This method takes a list of global property identifiers (not including a mapping to propety values) and
     * translates generated worker IDs and worker names.
     * This is used for the list of removed properties.
     * 
     * @param properties
     * @return Resulting list
     * @throws PropertiesApplierException
     */
    private List<PropertiesParser.GlobalProperty> translateGlobalProperties(final List<PropertiesParser.GlobalProperty> properties)
        throws PropertiesApplierException {
        final List<PropertiesParser.GlobalProperty> result = new LinkedList<PropertiesParser.GlobalProperty>();
        
        for (final PropertiesParser.GlobalProperty prop : properties) {
            result.add(new PropertiesParser.GlobalProperty(prop.getScope(), translateGlobalPropertyKey(prop.getKey())));
        }
        
        return result;
    }
    
    /**
     * Translate a mapping from worker property identifiers to values.
     * Translates genrated worker IDs and worker names to worker IDs.
     * 
     * @param workerProperties
     * @return Restulting mapping
     * @throws PropertiesApplierException
     */
    private Map<PropertiesParser.WorkerProperty, String> translateWorkerProperties(
            final Map<PropertiesParser.WorkerProperty, String> workerProperties)
            throws PropertiesApplierException {
        final Map<PropertiesParser.WorkerProperty, String> result =
                new HashMap<PropertiesParser.WorkerProperty, String>();
        
        for (final PropertiesParser.WorkerProperty prop : workerProperties.keySet()) {
            result.put(new PropertiesParser.WorkerProperty(Integer.toString(translateWorkerPropertyKey(prop.getWorkerIdOrName())),
                    prop.getKey()),
                    workerProperties.get(prop));
        }
        
        return result;
    }
    
    /**
     * Translate a list of worker property identifiers.
     * Translates generated worker IDs and worker names to worker IDs.
     * 
     * @param workerProperties
     * @return Resulting list
     * @throws PropertiesApplierException
     */
    private List<PropertiesParser.WorkerProperty> translateWorkerProperties(final List<PropertiesParser.WorkerProperty> workerProperties)
        throws PropertiesApplierException {
        final List<PropertiesParser.WorkerProperty> result = new LinkedList<PropertiesParser.WorkerProperty>();
        
        for (final PropertiesParser.WorkerProperty prop : workerProperties) {
            result.add(new PropertiesParser.WorkerProperty(Integer.toString(translateWorkerPropertyKey(prop.getWorkerIdOrName())),
                                                            prop.getKey()));
        }
        
        return result;
    }

    /**
     * Translate a mapping of worker names or IDs to assosiated data (used for the signer certificates and chains).
     * Translates generated worker IDs and worker names.
     * 
     * @param signerDataLists
     * @return Resulting mapping
     * @throws PropertiesApplierException
     */
    private <T> Map<Integer, T> translateWorkerDatas(final Map<String, T> signerDataLists)
        throws PropertiesApplierException {
        final Map<Integer, T> result = new HashMap<Integer, T>();
        
        for (final String workerNameOrId : signerDataLists.keySet()) {           
            result.put(translateWorkerPropertyKey(workerNameOrId), signerDataLists.get(workerNameOrId));
        }
        
        return result;
    }

    /**
     * Set a global property.
     * 
     * @param scope
     * @param key
     * @param value
     */
    protected abstract void setGlobalProperty(final String scope, final String key, final String value);
    
    /**
     * Remove a global property.
     * 
     * @param scope
     * @param key
     */
    protected abstract void removeGlobalProperty(final String scope, final String key);
    
    /**
     * Set a worker property.
     * 
     * @param workerId
     * @param key
     * @param value
     */
    protected abstract void setWorkerProperty(final int workerId, final String key, final String value);
    
    /**
     * Remove a worker property.
     * 
     * @param workerId
     * @param key
     */
    protected abstract void removeWorkerProperty(final int workerId, final String key);
    
    /**
     * Upload a signer certificate.
     * 
     * @param workerId
     * @param signerCert
     */
    protected abstract void uploadSignerCertificate(final int workerId, final byte[] signerCert);
    
    /**
     * Upload a signer certificate chain.
     * 
     * @param workerId
     * @param signerCertChain
     */
    protected abstract void uploadSignerCertificateChain(final int workerId, final List<byte[]> signerCertChain);
    
    /**
     * Add an authorized client for a worker.
     * 
     * @param workerId
     * @param ac Authorized client to add
     */
    protected abstract void addAuthorizedClient(final int workerId, final AuthorizedClient ac);
    
    /**
     * Remove an authorized client for a worker.
     * 
     * @param workerId
     * @param ac Authorized client to remove
     */
    protected abstract void removeAuthorizedClient(final int workerId, final AuthorizedClient ac);
    
    /**
     * Get the worker ID for an indexed generated worker ID.
     * 
     * @param splittedKey The referenced worker key in the form GENIDx
     * @return The worker ID
     */
    private int getGenId(String splittedKey) {
        if (genIds.get(splittedKey) == null) {
            int genid = genFreeWorkerId();
            genIds.put(splittedKey, new Integer(genid));
        }
        return ((Integer) genIds.get(splittedKey)).intValue();
    }

    /**
     * Lookup next available auto-generated worker ID.
     * 
     * @return Next available worker ID
     */
    protected abstract int genFreeWorkerId();
    
    /**
     * Lookup worker ID given name, implemenation-specific.
     * 
     * @param workerName
     * @return worker ID
     * @throws IllegalArgumentException if given a non-existing worker name
     */
    protected abstract int getWorkerId(final String workerName);
    
    /**
     * Get the worker ID from the splitted property key, either a number (ID), worker name or in the form GENIDx
     * 
     * @param splittedKey
     * @return worker ID
     */
    private int translateWorkerPropertyKey(final String splittedKey) {
        final int workerid;
        if (splittedKey.substring(0, 1).matches("\\d")) {
            workerid = Integer.parseInt(splittedKey);

        } else {
            if (splittedKey.startsWith(GENID)) {
                workerid = getGenId(splittedKey);
            } else {
                workerid = getWorkerId(splittedKey);
            }
        }
        
        workerIds.add(workerid);
        
        return workerid;
    }
    
    /**
     * Translate a global property.
     * Will map generated worker IDs and worker names to worker IDs.
     * 
     * @param propertyKey Property key
     * @return Translated property key
     */
    private String translateGlobalPropertyKey(final String propertyKey) {
        String strippedKey = propertyKey;
        String key = strippedKey;
        if (strippedKey.startsWith(WORKER_PREFIX + GENID)
                || strippedKey.startsWith(OLDWORKER_PREFIX + GENID)) {
            if (strippedKey.startsWith(WORKER_PREFIX)) {
                strippedKey = strippedKey.substring(WORKER_PREFIX.length());
            }
            if (strippedKey.startsWith(OLDWORKER_PREFIX)) {
                strippedKey = strippedKey.substring(OLDWORKER_PREFIX.length());
            }
            String splittedKey = strippedKey.substring(0, strippedKey.indexOf('.'));
            String propertykey = strippedKey.substring(strippedKey.indexOf('.') + 1);

            final int workerId = getGenId(splittedKey);
            
            workerIds.add(workerId);
            key = WORKER_PREFIX + workerId + "." + propertykey;

        } else {
            if (strippedKey.startsWith(WORKER_PREFIX) || strippedKey.startsWith(OLDWORKER_PREFIX)) {
                final String strippedKey2;
                if (strippedKey.startsWith(WORKER_PREFIX)) {
                    strippedKey2 = strippedKey.substring(WORKER_PREFIX.length());
                } else {
                    strippedKey2 = strippedKey.substring(OLDWORKER_PREFIX.length());
                }

                String splittedKey = strippedKey2.substring(0, strippedKey2.indexOf('.'));
                String propertykey = strippedKey2.substring(strippedKey2.indexOf('.') + 1);
                final int workerid;
                if (splittedKey.substring(0, 1).matches("\\d")) {
                    workerid = Integer.parseInt(splittedKey);
                } else {
                    workerid = getWorkerId(splittedKey);
                }
                
                workerIds.add(workerid);

                key = WORKER_PREFIX + workerid + "." + propertykey;
            }
        }
        
        return key;
    }
    
    /**
     * Return a list of worker IDs modified during application of the configuration.
     * 
     * @return List of worker IDs
     */
    public List<Integer> getWorkerIds() {
        return new ArrayList<Integer>(workerIds);
    }
}
