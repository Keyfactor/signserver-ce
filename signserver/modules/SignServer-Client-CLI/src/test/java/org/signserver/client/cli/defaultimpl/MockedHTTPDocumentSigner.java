/**
 *
 */
package org.signserver.client.cli.defaultimpl;

import java.util.Map;
import java.util.Optional;

/**
 *
 * @author Hanna Hansson
 */
public class MockedHTTPDocumentSigner extends HTTPDocumentSigner {

    private final String workerName;
    private final Optional<Integer> workerId;
    private final HostManager hostsManager;
    private final int port;
    final String baseUrlPath;
    private final String servlet;
    private final boolean useHTTPS;
    private String username;
    private String password;
    private String accessToken;
    private String pdfPassword;
    private Map<String, String> metadata;
    private final int timeOutLimit;

    public MockedHTTPDocumentSigner(HostManager hostsManager,
                                    int port,
                                    String baseUrlPath,
                                    String servlet,
                                    boolean useHTTPS,
                                    String workerName,
                                    String username,
                                    String password,
                                    String accessToken,
                                    String pdfPassword,
                                    Map<String, String> metadata,
                                    int timeOutLimit) {
        super(hostsManager, port, baseUrlPath,
                servlet, useHTTPS, workerName,
                username, password, accessToken,
                pdfPassword, metadata, timeOutLimit);
        this.hostsManager = hostsManager;
        this.port = port;
        this.baseUrlPath = baseUrlPath;
        this.servlet = servlet;
        this.useHTTPS = useHTTPS;
        this.workerName = workerName;
        this.workerId = Optional.empty();
        this.username = username;
        this.password = password;
        this.accessToken = accessToken;
        this.pdfPassword = pdfPassword;
        this.metadata = metadata;
        this.timeOutLimit = timeOutLimit;
    }

    public String getBaseUrlPath() {
        return this.baseUrlPath;
    }

}
