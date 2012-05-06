package org.signserver.server;

import org.signserver.common.RequestContext;
import org.signserver.server.IClientCredential;

public interface IWorkerLookup {

    String lookupClientAuthorizedWorker(IClientCredential credential, RequestContext context);
}
