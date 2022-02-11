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
import java.net.URL;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.MessageContext;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.signserver.common.*;
import org.signserver.testutils.ModulesTestCase;
import org.junit.Before;
import org.signserver.client.clientws.ClientWS;
import org.signserver.client.clientws.ClientWSService;
import org.signserver.client.clientws.DataResponse;
import org.signserver.client.clientws.InternalServerException_Exception;
import org.signserver.client.clientws.Metadata;
import org.signserver.client.clientws.RequestFailedException_Exception;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Re-usable test case for archiving.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ArchiveTestCase extends ModulesTestCase {

    private final Random RANDOM = new Random();

    private final WorkerSession workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();
    private SSLSocketFactory socketFactory;

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        socketFactory = setupSSLKeystores();
    }

    @After
    public void tearDown() throws Exception {
    }

    private DataResponse processWithClientWS(WorkerIdentifier wi, byte[] document, final String xForwardedFor) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, InternalServerException_Exception, RequestFailedException_Exception {
        final URL resource =
                getClass().getResource("/org/signserver/protocol/client/ws/ClientWS.wsdl");
        final String url = "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() + "/signserver/ClientWSService/ClientWS?wsdl";
        final ClientWSService service =
                new ClientWSService(resource, new QName("http://clientws.signserver.org/", "ClientWSService"));
        final ClientWS wsPort = service.getClientWSPort();

        final BindingProvider bp = (BindingProvider) wsPort;
        final Map<String, Object> requestContext = bp.getRequestContext();

        requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, url);

        if (socketFactory != null) {
            final Client client = ClientProxy.getClient(bp);
            final HTTPConduit http = (HTTPConduit) client.getConduit();
            final TLSClientParameters params = new TLSClientParameters();

            params.setSSLSocketFactory(socketFactory);
            http.setTlsClientParameters(params);
        }

        // Add HTTP header
        if (xForwardedFor != null) {
            requestContext.put(MessageContext.HTTP_REQUEST_HEADERS,
                    Collections.singletonMap("X-Forwarded-For", Collections.singletonList(xForwardedFor)));
        }
        return wsPort.processData(wi.hasName() ? wi.getName() : String.valueOf(wi.getId()), Collections.<Metadata>emptyList(), document);
    }

    protected ArchiveDataVO testArchive(final String document, final String xForwardedFor) throws Exception {
        // Process
        DataResponse response = processWithClientWS(new WorkerIdentifier(getSignerIdDummy1()), document.getBytes(), xForwardedFor);
        assertNotNull("no response", response);

        final String expectedArchiveId = response.getArchiveId();

        List<ArchiveDataVO> archiveDatas = getWorkerSession().findArchiveDataFromArchiveId(getSignerIdDummy1(), expectedArchiveId);
        ArchiveDataVO archiveData = archiveDatas.get(0);
        assertEquals("same ID in db",
                expectedArchiveId, archiveData.getArchiveId());
        assertEquals("same signer ID in db",
                getSignerIdDummy1(), archiveData.getSignerId());

        return archiveData;
    }

    protected ArchiveDataVO testArchive(final String document) throws Exception {
        return testArchive(document, null);
    }

    protected void testNoArchive(final String document) throws Exception {
        // Process
        final GenericSignRequest signRequest =
                new GenericSignRequest(371, document.getBytes());
        GenericSignResponse response = (GenericSignResponse)
                processSession.process(new WorkerIdentifier(getSignerIdDummy1()), signRequest,
                new RemoteRequestContext());
        assertNotNull("no response", response);

        final String expectedArchiveId = response.getArchiveId();

        List<ArchiveDataVO> archiveDatas = getWorkerSession().findArchiveDataFromArchiveId(getSignerIdDummy1(), expectedArchiveId);
        assertEquals("no archivedata in db", 0, archiveDatas.size());
    }

    protected void archiveOnlyResponse(final int signerId) throws Exception {
        final int reqid = RANDOM.nextInt();

        final TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.2.3"));
        final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final byte[] requestBytes = timeStampRequest.getEncoded();

        final GenericSignRequest signRequest = new GenericSignRequest(reqid, requestBytes);

        final GenericSignResponse signResponse = (GenericSignResponse) processSession.process(
                new WorkerIdentifier(signerId), signRequest, new RemoteRequestContext());
        assertNotNull("no response", signResponse);
        final byte[] responseBytes = signResponse.getProcessedData();
        final String responseHex = new String(Hex.encode(responseBytes));

        final Collection<? extends Archivable> archivables = signResponse.getArchivables();

        assertEquals("two response", 2, archivables.size());

        final Iterator<? extends Archivable> iterator = archivables.iterator();
        final Archivable first = iterator.next();
        final Archivable second = iterator.next();
        final Archivable response;

        if (first.getType().equals(Archivable.TYPE_REQUEST)) {
            response = second;
        } else {
            response = first;
        }

        final String archiveId = response.getArchiveId();

        assertEquals("same archiveId for all", archiveId, response.getArchiveId());

        final List<ArchiveDataVO> allArchiveData = getWorkerSession().findArchiveDataFromArchiveId(signerId, archiveId);

        assertEquals("one response", 1, allArchiveData.size());

        final ArchiveDataVO responseArchiveData = allArchiveData.get(0);

        assertEquals("same archiveId for all", archiveId, responseArchiveData.getArchiveId());

        assertEquals("same response", responseHex, new String(Hex.encode(responseArchiveData.getArchivedBytes())));
    }

    protected void archiveOnlyRequest(final int signerId) throws Exception {
        final int reqid = RANDOM.nextInt();

        final TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.2.3"));
        final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final byte[] requestBytes = timeStampRequest.getEncoded();
        final String requestHex = new String(Hex.encode(requestBytes));

        final GenericSignRequest signRequest = new GenericSignRequest(reqid, requestBytes);

        final GenericSignResponse signResponse = (GenericSignResponse) processSession.process(
                new WorkerIdentifier(signerId), signRequest, new RemoteRequestContext());
        assertNotNull("no response", signResponse);

        final Collection<? extends Archivable> archivables = signResponse.getArchivables();

        assertEquals("two response", 2, archivables.size());

        final Iterator<? extends Archivable> iterator = archivables.iterator();
        final Archivable first = iterator.next();
        final Archivable second = iterator.next();
        final Archivable request;

        if (first.getType().equals(Archivable.TYPE_REQUEST)) {
            request = first;
        } else {
            request = second;
        }

        final String archiveId = request.getArchiveId();

        assertEquals("same archiveId for all", archiveId, request.getArchiveId());

        final List<ArchiveDataVO> allArchiveData = getWorkerSession().findArchiveDataFromArchiveId(signerId, archiveId);

        assertEquals("one request", 1, allArchiveData.size());

        final ArchiveDataVO responseArchiveData = allArchiveData.get(0);

        assertEquals("same archiveId for all", archiveId, responseArchiveData.getArchiveId());

        assertEquals("same request", requestHex, new String(Hex.encode(responseArchiveData.getArchivedBytes())));
    }

    protected void archiveRequestAndResponse(final int signerId) throws Exception {
        final int reqid = RANDOM.nextInt();

        final TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.2.3"));
        final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final byte[] requestBytes = timeStampRequest.getEncoded();
        final String requestHex = new String(Hex.encode(requestBytes));

        final GenericSignRequest signRequest = new GenericSignRequest(reqid, requestBytes);

        final GenericSignResponse signResponse = (GenericSignResponse) processSession.process(
                new WorkerIdentifier(signerId), signRequest, new RemoteRequestContext());
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

        assertEquals("same ID in db", archiveId, requestArchiveData.getArchiveId());
        assertEquals("same signer ID in db", signerId, requestArchiveData.getSignerId());
        assertEquals("same archived data", requestHex, new String(Hex.encode(requestArchiveData.getArchivedBytes())));

        assertEquals("same ID in db", archiveId, responseArchiveData.getArchiveId());
        assertEquals("same signer ID in db", signerId, responseArchiveData.getSignerId());
        assertEquals("same archived data", requestHex, new String(Hex.encode(requestArchiveData.getArchivedBytes())));

    }

}
