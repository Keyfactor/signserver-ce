package org.signserver.server;

import org.signserver.common.RequestContext;

public interface IWorkerLookup {

    String lockupClientAuthorizedWorker(IClientCredential credential, RequestContext context);
}
