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

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.ejbca.util.Base64;
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
    
    private List<PropertiesParser.GlobalProperty> translateGlobalProperties(final List<PropertiesParser.GlobalProperty> properties)
        throws PropertiesApplierException {
        final List<PropertiesParser.GlobalProperty> result = new LinkedList<PropertiesParser.GlobalProperty>();
        
        for (final PropertiesParser.GlobalProperty prop : properties) {
            result.add(new PropertiesParser.GlobalProperty(prop.getScope(), translateGlobalPropertyKey(prop.getKey())));
        }
        
        return result;
    }
    
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
    
    private List<PropertiesParser.WorkerProperty> translateWorkerProperties(final List<PropertiesParser.WorkerProperty> workerProperties)
        throws PropertiesApplierException {
        final List<PropertiesParser.WorkerProperty> result = new LinkedList<PropertiesParser.WorkerProperty>();
        
        for (final PropertiesParser.WorkerProperty prop : workerProperties) {
            result.add(new PropertiesParser.WorkerProperty(Integer.toString(translateWorkerPropertyKey(prop.getWorkerIdOrName())),
                                                            prop.getKey()));
        }
        
        return result;
    }

    private <T> Map<Integer, T> translateWorkerDatas(final Map<String, T> signerDataLists)
        throws PropertiesApplierException {
        final Map<Integer, T> result = new HashMap<Integer, T>();
        
        for (final String workerNameOrId : signerDataLists.keySet()) {           
            result.put(translateWorkerPropertyKey(workerNameOrId), signerDataLists.get(workerNameOrId));
        }
        
        return result;
    }

    protected abstract void setGlobalProperty(final String scope, final String key, final String value);
    protected abstract void removeGlobalProperty(final String scope, final String key);
    protected abstract void setWorkerProperty(final int workerId, final String key, final String value);
    protected abstract void removeWorkerProperty(final int workerId, final String key);
    protected abstract void uploadSignerCertificate(final int workerId, final byte[] signerCert);
    protected abstract void uploadSignerCertificateChain(final int workerId, final List<byte[]> signerCertChain);
    protected abstract void addAuthorizedClient(final int workerId, final AuthorizedClient ac);
    protected abstract void removeAuthorizedClient(final int workerId, final AuthorizedClient ac);
    
    /**
     * Get the worker ID for an indexed generated worker ID.
     * 
     * @param splittedKey The referenced worker key in the form GENIDx
     * @return The worker ID
     */
    private int getGenId(String splittedKey) throws PropertiesApplierException {
        if (genIds.get(splittedKey) == null) {
            int genid = genFreeWorkerId();
            genIds.put(splittedKey, new Integer(genid));
        }
        return ((Integer) genIds.get(splittedKey)).intValue();
    }

    /**
     * Lookup next available auto-generated worker ID.
     * 
     * @return
     */
    protected abstract int genFreeWorkerId() throws PropertiesApplierException;
    
    /**
     * Lookup worker ID given name, implemenation-specific.
     * 
     * @param workerName
     * @return worker ID
     * @throws IllegalArgumentException if given a non-existing worker name
     */
    protected abstract int getWorkerId(final String workerName) throws PropertiesApplierException;
    
    /**
     * Get the worker ID from the splitted property key, either a number (ID), worker name or in the form GENIDx
     * 
     * @param splittedKey
     * @return worker ID
     */
    private int translateWorkerPropertyKey(final String splittedKey) throws PropertiesApplierException {
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
        
        return workerid;
    }
    
    private String translateGlobalPropertyKey(final String propertyKey) throws PropertiesApplierException {
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

            key = WORKER_PREFIX + getGenId(splittedKey) + "." + propertykey;

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

                key = WORKER_PREFIX + workerid + "." + propertykey;
            }
        }
        
        return key;
    }
}
