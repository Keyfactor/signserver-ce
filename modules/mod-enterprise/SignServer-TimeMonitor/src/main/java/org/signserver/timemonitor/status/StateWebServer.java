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
package org.signserver.timemonitor.status;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;

import org.signserver.timemonitor.common.LeapState;
import org.signserver.timemonitor.common.ReportState;
import org.signserver.timemonitor.core.StateHolder;
import org.signserver.timemonitor.common.TimeState;

/**
 * Web server offering the current states and the last update time.
 *
 * @author Markus Kilås
 * @version $Id: StateWebServer.java 4569 2012-12-10 14:11:57Z marcus $
 */
public class StateWebServer {

    private final StateHolder stateHolder;
    private final InetAddress bindAddress;
    private final int port;
    private final int backlog;
    private final int threads;

    private HttpServer server;

    /**
     * Creates an new instance of StateWebServer.
     * @param stateHolder Holder capable of giving the current state
     * @param bindAddress Local address to bind to
     * @param port Port to listen on
     * @param backlog Number of waiting threads to hold in queue
     * @param threads Number of threads serving the status
     */
    public StateWebServer(final StateHolder stateHolder, final InetAddress bindAddress, final int port, final int backlog, final int threads) {
        this.stateHolder = stateHolder;
        this.bindAddress = bindAddress;
        this.port = port;
        this.backlog = backlog;
        this.threads = threads;
    }

    /**
     * Starts the web service
     * @throws IOException In case the port was already in use etc
     */
    public void start() throws IOException {
        InetSocketAddress addr = new InetSocketAddress(bindAddress, port);
        server = HttpServer.create(addr, backlog);

        server.createContext("/state", createHttpHandler());
        if (threads == 0) {
            server.setExecutor(Executors.newCachedThreadPool());
        } else {
            server.setExecutor(Executors.newFixedThreadPool(threads));
        }
        server.start();
    }

    public void stop(final int delay) {
        if (server != null) {
            server.stop(delay);
        }
    }

    protected HttpHandler createHttpHandler() {
        return new StateWebHttpHandler();
    }

    private class StateWebHttpHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            String requestMethod = exchange.getRequestMethod();
            if (requestMethod.equalsIgnoreCase("GET")) {
                final Headers responseHeaders = exchange.getResponseHeaders();
                responseHeaders.set("Content-Type", "text/plain");
                responseHeaders.set("Cache-Control", "no-cache");

                final byte[] report = stateHolder.getStateLine().toString().getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, report.length);
                try (OutputStream responseBody = exchange.getResponseBody()) {
                    responseBody.write(report);
                }
            }
        }
    }
}
