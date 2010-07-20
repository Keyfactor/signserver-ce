package org.signserver.server;

import org.signserver.common.RequestContext;

public interface IWorkerLookup {

    String lookupClientAuthorizedWorker(IClientCredential credential, RequestContext context);
}
