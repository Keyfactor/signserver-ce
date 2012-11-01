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
package org.signserver.server.archive;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.*;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Re-usable test case for archiving.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ArchiveTestCase extends ModulesTestCase {
    
    private Random random = new Random();
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
//        TestingSecurityManager.install();
        String signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }	
    
    protected ArchiveDataVO testArchive(final String document, final String remoteIP, final String xForwardedFor) throws Exception {
        // Process
        final GenericSignRequest signRequest =
                new GenericSignRequest(371, document.getBytes());
        final RequestContext context =  new RequestContext();
        
        if (remoteIP != null) {
            context.put(RequestContext.REMOTE_IP, remoteIP);
        }
        
        if (xForwardedFor != null) {
            context.put(RequestContext.X_FORWARDED_FOR, xForwardedFor);
        }
        
        GenericSignResponse response = (GenericSignResponse) 
                workerSession.process(getSignerIdDummy1(), signRequest, 
                context);
        assertNotNull("no response", response);
        
        final String expectedArchiveId = response.getArchiveId();
        final Archivable expectedArchiveData = response.getArchivables().iterator().next();
        
        List<ArchiveDataVO> archiveDatas = getWorkerSession().findArchiveDataFromArchiveId(getSignerIdDummy1(), expectedArchiveId);
        ArchiveDataVO archiveData = archiveDatas.get(0);
        assertEquals("same id in db", 
                expectedArchiveId, archiveData.getArchiveId());
        assertEquals("same signer id in db", 
                getSignerIdDummy1(), archiveData.getSignerId());
        
        assertTrue("same archived data", 
                Arrays.equals(expectedArchiveData.getContentEncoded(), 
                archiveData.getArchivedBytes()));
        return archiveData;
    }
    
    protected ArchiveDataVO testArchive(final String document) throws Exception {
        return testArchive(document, null, null);
    }
    
    protected void testNoArchive(final String document) throws Exception {
        // Process
        final GenericSignRequest signRequest =
                new GenericSignRequest(371, document.getBytes());
        GenericSignResponse response = (GenericSignResponse) 
                workerSession.process(getSignerIdDummy1(), signRequest, 
                new RequestContext());
        assertNotNull("no response", response);
        
        final String expectedArchiveId = response.getArchiveId();
        
        List<ArchiveDataVO> archiveDatas = getWorkerSession().findArchiveDataFromArchiveId(getSignerIdDummy1(), expectedArchiveId);
        assertEquals("no archivedata in db", 0, archiveDatas.size());
    }
    
    protected void archiveOnlyResponse(final int signerId) throws Exception {
        final int reqid = random.nextInt();

        final TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.2.3"));
        final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final byte[] requestBytes = timeStampRequest.getEncoded();
        final String requestHex = new String(Hex.encode(requestBytes));

        final GenericSignRequest signRequest = new GenericSignRequest(reqid, requestBytes);

        final GenericSignResponse signResponse = (GenericSignResponse) workerSession.process(
                signerId, signRequest, new RequestContext());
        assertNotNull("no response", signResponse);
        final byte[] responseBytes = signResponse.getProcessedData();
        final String responseHex = new String(Hex.encode(responseBytes));
        
        final Collection<? extends Archivable> archivables = signResponse.getArchivables();
        
        assertEquals("two response", 2, archivables.size());
        
        final Iterator<? extends Archivable> iterator = archivables.iterator();
        final Archivable first = iterator.next();
        final Archivable second = iterator.next();
        final Archivable request;
        final Archivable response;
        
        if (first.getType().equals(Archivable.TYPE_REQUEST)) {
            request = first;
            response = second;
        } else {
            request = second;
            response = first;
        }
        
        final String archiveId = response.getArchiveId();
        
        assertEquals("same archiveId for all", archiveId, response.getArchiveId());
        
        assertEquals("same response", responseHex, new String(Hex.encode(response.getContentEncoded())));
        assertEquals("same request", requestHex, new String(Hex.encode(request.getContentEncoded())));
        
        final List<ArchiveDataVO> allArchiveData = getWorkerSession().findArchiveDataFromArchiveId(signerId, archiveId);
        
        assertEquals("one response", 1, allArchiveData.size());
        
        final ArchiveDataVO responseArchiveData = allArchiveData.get(0);
        
        assertEquals("same archiveId for all", archiveId, responseArchiveData.getArchiveId());
        
        assertEquals("same response", responseHex, new String(Hex.encode(responseArchiveData.getArchivedBytes())));
    }
    
    protected void archiveOnlyRequest(final int signerId) throws Exception {
        final int reqid = random.nextInt();

        final TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.2.3"));
        final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final byte[] requestBytes = timeStampRequest.getEncoded();
        final String requestHex = new String(Hex.encode(requestBytes));

        final GenericSignRequest signRequest = new GenericSignRequest(reqid, requestBytes);

        final GenericSignResponse signResponse = (GenericSignResponse) workerSession.process(
                signerId, signRequest, new RequestContext());
        assertNotNull("no response", signResponse);
        final byte[] responseBytes = signResponse.getProcessedData();
        final String responseHex = new String(Hex.encode(responseBytes));
        
        final Collection<? extends Archivable> archivables = signResponse.getArchivables();
        
        assertEquals("two response", 2, archivables.size());
        
        final Iterator<? extends Archivable> iterator = archivables.iterator();
        final Archivable first = iterator.next();
        final Archivable second = iterator.next();
        final Archivable request;
        final Archivable response;
        
        if (first.getType().equals(Archivable.TYPE_REQUEST)) {
            request = first;
            response = second;
        } else {
            request = second;
            response = first;
        }
        
        final String archiveId = request.getArchiveId();
        
        assertEquals("same archiveId for all", archiveId, response.getArchiveId());
        
        assertEquals("same response", responseHex, new String(Hex.encode(response.getContentEncoded())));
        assertEquals("same request", requestHex, new String(Hex.encode(request.getContentEncoded())));
        
        final List<ArchiveDataVO> allArchiveData = getWorkerSession().findArchiveDataFromArchiveId(signerId, archiveId);
        
        assertEquals("one request", 1, allArchiveData.size());
        
        final ArchiveDataVO responseArchiveData = allArchiveData.get(0);
        
        assertEquals("same archiveId for all", archiveId, responseArchiveData.getArchiveId());
        
        assertEquals("same request", requestHex, new String(Hex.encode(responseArchiveData.getArchivedBytes())));
    }
    
    protected void archiveRequestAndResponse(final int signerId) throws Exception {
        final int reqid = random.nextInt();

        final TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.2.3"));
        final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final byte[] requestBytes = timeStampRequest.getEncoded();
        final String requestHex = new String(Hex.encode(requestBytes));

        final GenericSignRequest signRequest = new GenericSignRequest(reqid, requestBytes);

        final GenericSignResponse signResponse = (GenericSignResponse) workerSession.process(
                signerId, signRequest, new RequestContext());
        assertNotNull("no response", signResponse);
        final byte[] responseBytes = signResponse.getProcessedData();
        final String responseHex = new String(Hex.encode(responseBytes));
        
        final Collection<? extends Archivable> archivables = signResponse.getArchivables();
        
        assertEquals("two responses", 2, archivables.size());
        
        final Iterator<? extends Archivable> iterator = archivables.iterator();
        final Archivable first = iterator.next();
        final Archivable second = iterator.next();
        final Archivable request;
        final Archivable response;
        
        if (first.getType().equals(Archivable.TYPE_REQUEST)) {
            request = first;
            response = second;
        } else {
            request = second;
            response = first;
        }
        
        final String archiveId = request.getArchiveId();
        
        assertEquals("same archiveId for all", archiveId, response.getArchiveId());
        
        assertEquals("same response", responseHex, new String(Hex.encode(response.getContentEncoded())));
        assertEquals("same request", requestHex, new String(Hex.encode(request.getContentEncoded())));
        
        final List<ArchiveDataVO> allArchiveData = getWorkerSession().findArchiveDataFromArchiveId(signerId, archiveId);
        
        assertEquals("two responses", 2, allArchiveData.size());
        
        final ArchiveDataVO firstArchiveData = allArchiveData.get(0);
        final ArchiveDataVO secondArchiveData = allArchiveData.get(1);
        final ArchiveDataVO requestArchiveData;
        final ArchiveDataVO responseArchiveData;
        
        if (firstArchiveData.getType() == ArchiveDataVO.TYPE_REQUEST) {
            requestArchiveData = firstArchiveData;
            responseArchiveData = secondArchiveData;
        } else {
            requestArchiveData = secondArchiveData;
            responseArchiveData = firstArchiveData;
        }
        
        assertEquals("same archiveId for all", archiveId, responseArchiveData.getArchiveId());
        
        assertEquals("same response", responseHex, new String(Hex.encode(responseArchiveData.getArchivedBytes())));
        assertEquals("same request", requestHex, new String(Hex.encode(requestArchiveData.getArchivedBytes())));
        
        assertEquals("same id in db", archiveId, requestArchiveData.getArchiveId());
        assertEquals("same signer id in db", signerId, requestArchiveData.getSignerId());
        assertEquals("same archived data", requestHex, new String(Hex.encode(requestArchiveData.getArchivedBytes())));
        
        assertEquals("same id in db", archiveId, responseArchiveData.getArchiveId());
        assertEquals("same signer id in db", signerId, responseArchiveData.getSignerId());
        assertEquals("same archived data", requestHex, new String(Hex.encode(requestArchiveData.getArchivedBytes())));
        
    }
    
}
