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
package org.signserver.server.archive.olddbarchiver.entities;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.common.ArchiveData;

/**
 * Entity Service class that acts as migration layer for
 * the old Home Interface for the Archive Data Entity Bean.
 *
 * Contains about the same methods as the EJB 2 entity beans home interface.
 *
 * @version $Id$
 */
public class ArchiveDataService {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ArchiveDataService.class);
    
    private EntityManager em;

    public ArchiveDataService(EntityManager em) {
        this.em = em;
    }

    /**
     * Entity Bean holding info about a archive data.
     */
    public String create(int type, int signerId, String archiveid, X509Certificate clientCert,
            String requestIP, ArchiveData archiveData) {
        String uniqueId = type + ";" + signerId + ";" + archiveid;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating archive data, uniqueId=" + uniqueId);
        }
        ArchiveDataBean adb = new ArchiveDataBean();
        adb.setUniqueId(uniqueId);
        adb.setType(type);
        adb.setSignerid(signerId);
        adb.setTime(new Date().getTime());
        adb.setArchiveid(archiveid);
        if (clientCert != null) {
            adb.setRequestIssuerDN(CertTools.getIssuerDN(clientCert));
            adb.setRequestCertSerialnumber(clientCert.getSerialNumber().toString(16));
        }
        adb.setRequestIP(requestIP);
        adb.setArchiveDataObject(archiveData);
        adb.setDataEncoding(ArchiveDataBean.DATA_ENCODING_XML);

        em.persist(adb);
        return uniqueId;
    }
    
    public String create(int type, int signerId, String archiveid, X509Certificate clientCert,
            String requestIP, String archiveData) {
        String uniqueId = type + ";" + signerId + ";" + archiveid;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating archive data, uniqueId=" + uniqueId);
        }
        ArchiveDataBean adb = new ArchiveDataBean();
        adb.setUniqueId(uniqueId);
        adb.setType(type);
        adb.setSignerid(signerId);
        adb.setTime(new Date().getTime());
        adb.setArchiveid(archiveid);
        if (clientCert != null) {
            adb.setRequestIssuerDN(CertTools.getIssuerDN(clientCert));
            adb.setRequestCertSerialnumber(clientCert.getSerialNumber().toString(16));
        }
        adb.setRequestIP(requestIP);
        adb.setArchiveData(archiveData);
        adb.setDataEncoding(ArchiveDataBean.DATA_ENCODING_BASE64);
 
        em.persist(adb);
        return uniqueId;
    }

    /**
     * Method finding a AchiveData given its unique Id.
     */
    public ArchiveDataBean findByArchiveId(int type, int signerid, java.lang.String archiveid) {
        try {
            return (ArchiveDataBean) em.createNamedQuery("ArchiveDataBean.findByArchiveId").setParameter(1, type).setParameter(2, signerid).setParameter(3, archiveid).getSingleResult();
        } catch (javax.persistence.NoResultException e) {
        }
        return null;
    }
    
    /**
     * Method finding all ArchiveDataBeans given the archiveId.
     */
    public List findAllByArchiveId(final int signerid, final String archiveid) {
        try {
            return em.createNamedQuery("ArchiveDataBean.findAllByArchiveId").setParameter(1, signerid).setParameter(2, archiveid).getResultList();
        } catch (NoResultException e) {
            return Collections.emptyList();
        }
    }

    @SuppressWarnings("unchecked")
    public java.util.Collection<ArchiveDataBean> findByTime(int type, int signerid, long starttime, long endtime) {
        try {
            return em.createNamedQuery("ArchiveDataBean.findByTime").setParameter(1, type).setParameter(2, signerid).setParameter(3, starttime).setParameter(4, endtime).getResultList();
        } catch (javax.persistence.NoResultException e) {
        }
        return new ArrayList<ArchiveDataBean>();
    }

    @SuppressWarnings("unchecked")
    public java.util.Collection<ArchiveDataBean> findByRequestCertificate(int type, int signerid, java.lang.String requestIssuerDN, java.lang.String requestCertSerialnumber) {
        try {
            return em.createNamedQuery("ArchiveDataBean.findByRequestCertificate").setParameter(1, type).setParameter(2, signerid).setParameter(3, requestIssuerDN).setParameter(4, requestCertSerialnumber).getResultList();
        } catch (javax.persistence.NoResultException e) {
        }
        return new ArrayList<ArchiveDataBean>();
    }

    @SuppressWarnings("unchecked")
    public java.util.Collection<ArchiveDataBean> findByRequestCertificateAndTime(int type, int signerid, java.lang.String requestIssuerDN, java.lang.String requestCertSerialnumber, long starttime, long endtime) {
        try {
            return em.createNamedQuery("ArchiveDataBean.findByRequestCertificateAndTime").setParameter(1, type).setParameter(2, signerid).setParameter(3, requestIssuerDN).setParameter(4, requestCertSerialnumber).setParameter(5, starttime).setParameter(6, endtime).getResultList();
        } catch (javax.persistence.NoResultException e) {
        }
        return new ArrayList<ArchiveDataBean>();
    }

    @SuppressWarnings("unchecked")
    public java.util.Collection<ArchiveDataBean> findByRequestIP(int type, int signerid, java.lang.String requestIP) {
        try {
            return em.createNamedQuery("ArchiveDataBean.findByRequestIP").setParameter(1, type).setParameter(2, signerid).setParameter(3, requestIP).getResultList();
        } catch (javax.persistence.NoResultException e) {
        }
        return new ArrayList<ArchiveDataBean>();
    }

    @SuppressWarnings("unchecked")
    public java.util.Collection<ArchiveDataBean> findByRequestIPAndTime(int type, int signerid, java.lang.String requestIP, long starttime, long endtime) {
        try {
            return em.createNamedQuery("ArchiveDataBean.findByRequestCertificateAndTime").setParameter(1, type).setParameter(2, signerid).setParameter(3, requestIP).setParameter(4, starttime).setParameter(5, endtime).getResultList();
        } catch (javax.persistence.NoResultException e) {
        }
        return new ArrayList<ArchiveDataBean>();
    }
}
