//
// ========================================================================
// Copyright (c) 1995-2020 Mort Bay Consulting Pty Ltd and others.
//
// This program and the accompanying materials are made available under
// the terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0
//
// This Source Code may also be made available under the following
// Secondary Licenses when the conditions for such availability set
// forth in the Eclipse Public License, v. 2.0 are satisfied:
// the Apache License v2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
// ========================================================================
//

package org.signserver.web.filters; 

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import javax.ejb.EJB;
import javax.servlet.AsyncContext;
import javax.servlet.AsyncListener;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.signserver.common.qos.AbstractStatistics;
import static org.signserver.common.GlobalConfiguration.SCOPE_GLOBAL;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.ejb.interfaces.GlobalConfigurationSession;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.web.ServletUtils;

/**
 * Quality of Service Filter.
 * <p>
 * This filter limits the number of active requests to the number set by the "maxRequests" init parameter (default 10).
 * If more requests are received, they are suspended and placed on priority queues.  Priorities are determined by
 * the {@link #getPriority(ServletRequest)} method and are a value between 0 and the value given by the "maxPriority"
 * init parameter (default 10), with higher values having higher priority.
 * <p>
 * This filter is ideal to prevent wasting threads waiting for slow/limited
 * resources such as a JDBC connection pool.  It avoids the situation where all of a
 * containers thread pool may be consumed blocking on such a slow resource.
 * By limiting the number of active threads, a smaller thread pool may be used as
 * the threads are not wasted waiting.  Thus more memory may be available for use by
 * the active threads.
 * <p>
 * Furthermore, this filter uses a priority when resuming waiting requests. So that if
 * a container is under load, and there are many requests waiting for resources,
 * the {@link #getPriority(ServletRequest)} method is used, so that more important
 * requests are serviced first.     For example, this filter could be deployed with a
 * maxRequest limit slightly smaller than the containers thread pool and a high priority
 * allocated to admin users.  Thus regardless of load, admin users would always be
 * able to access the web application.
 * <p>
 * The maxRequest limit is policed by a {@link Semaphore} and the filter will wait a short while attempting to acquire
 * the semaphore. This wait is controlled by the "waitMs" init parameter and allows the expense of a suspend to be
 * avoided if the semaphore is shortly available.  If the semaphore cannot be obtained, the request will be suspended
 * for the default suspend period of the container or the valued set as the "suspendMs" init parameter.
 * <p>
 * If the "managedAttr" init parameter is set to true, then this servlet is set as a {@link ServletContext} attribute with the
 * filter name as the attribute name.  This allows context external mechanism (eg JMX via {@link ContextHandler#MANAGED_ATTRIBUTES}) to
 * manage the configuration of the filter.
 */
//J @ManagedObject("Quality of Service Filter")
@WebFilter(asyncSupported = true)
public class QoSFilter implements Filter
{
    private static final Logger LOG = Logger.getLogger(QoSFilter.class);

    static final int __DEFAULT_MAX_PRIORITY = 5;
    static final int __DEFAULT_PASSES = 10;
    static final int __DEFAULT_WAIT_MS = 50;
    static final long __DEFAULT_TIMEOUT_MS = -1;

    static private final int CONFIG_CACHE_TIMEOUT = 10;

    static final String MANAGED_ATTR_INIT_PARAM = "managedAttr";
    static final String MAX_WAIT_INIT_PARAM = "waitMs";
    static final String SUSPEND_INIT_PARAM = "suspendMs";

    // global config params
    private enum GlobalProperty {
        QOS_FILTER_ENABLED,
        QOS_MAX_REQUESTS,
        QOS_MAX_PRIORITY,
        QOS_PRIORITIES
    };

    private final String _suspended = "QoSFilter@" + Integer.toHexString(hashCode()) + ".SUSPENDED";
    private final String _resumed = "QoSFilter@" + Integer.toHexString(hashCode()) + ".RESUMED";
    private long _waitMs;
    private long _suspendMs;
    private int _maxRequests;
    private Semaphore _passes;
    private ArrayList<Queue<AsyncContext>> _queues;
    private int maxPriorityLevel;

    // cache for global property values
    private Map<String, String> globalPropertyCache;
    private long globalPropertyCacheLastUpdated;

    private Map<Integer, Integer> workerPriorities;
    
    // request attributes
    public static String QOS_PRIORITY_ATTRIBUTE = "QOS_PRIORITY";
    
    @EJB
    private GlobalConfigurationSessionLocal globalSession;

    @EJB
    private WorkerSessionLocal workerSession;

    public List<Queue<AsyncContext>> getQueues() {
        return _queues;
    }

    private ArrayList<AsyncListener> _listeners;

    // Preliminary global properties for setting up filter:
    // GLOB.QOS_FILTER_ENABLED=true (to enable filter), default false (not enabled)
    // GLOB.QOS_MAX_REQUESTS=<maximum number of concurrent requests to be
    //                        accepted before queueing requests based on priority>
    // GLOB.QOS_MAX_PRIORITY=<maximum priority level to use>
    // GLOB.QOS_PRIORITIES=<comma-separated list of workerID:priority pairs>
    //
    // Example: GLOB.QOS_PRIORITIES=1:1,2:2,3:5

    @Override
    public void init(final FilterConfig filterConfig)
    {
        recreateGlobalPropertyCache();

        int maxRequests = getMaxRequestsFromConfig().orElse(__DEFAULT_PASSES);

        _passes = new Semaphore(maxRequests, true);
        _maxRequests = maxRequests;

        long wait = __DEFAULT_WAIT_MS;
        if (filterConfig.getInitParameter(MAX_WAIT_INIT_PARAM) != null)
            wait = Integer.parseInt(filterConfig.getInitParameter(MAX_WAIT_INIT_PARAM));
        _waitMs = wait;

        long suspend = __DEFAULT_TIMEOUT_MS;
        if (filterConfig.getInitParameter(SUSPEND_INIT_PARAM) != null)
            suspend = Integer.parseInt(filterConfig.getInitParameter(SUSPEND_INIT_PARAM));
        _suspendMs = suspend;

        ServletContext context = filterConfig.getServletContext();
        if (context != null && Boolean.parseBoolean(filterConfig.getInitParameter(MANAGED_ATTR_INIT_PARAM)))
            context.setAttribute(filterConfig.getFilterName(), this);

        createQueuesAndListeners(getMaxPriorityLevelFromConfig().orElse(__DEFAULT_MAX_PRIORITY));

        AbstractStatistics.setDefaultInstance(new QoSStatistics(this));
    }

    /**
     * Re-create the global property cache and the worker-priority mapping.
     */
    void recreateGlobalPropertyCache() {
        globalPropertyCache = new HashMap<>();

        for (final GlobalProperty property : GlobalProperty.values()) {
            final String key = property.name();
            globalPropertyCache.put(key, getGlobalProperty(key));
        }

        final String priorityMappingString = getGlobalProperty("QOS_PRIORITIES");

        workerPriorities = new HashMap<>();

        if (priorityMappingString != null) {
            try {
                workerPriorities = createPriorityMap(priorityMappingString);
            } catch (IllegalArgumentException e) {
                LOG.error("Failed to create priorities: " + e.getMessage());
            }
        }
        
        globalPropertyCacheLastUpdated = System.currentTimeMillis();
    }

    /**
     * Get a global property (with scope GLOB) from the global configuration
     * session.
     *
     * @param property name of property to set (not including the GLOB prefix)
     * @return property value, or null if not set
     */
    private String getGlobalProperty(final String property) {
        return getGlobalConfigurationSession().getGlobalConfiguration().
                getProperty(SCOPE_GLOBAL, property);
    }

    /**
     * Get global session (can be overridden by tests to use a mocked session).
     *
     * @return the global configuration session
     */
    GlobalConfigurationSession getGlobalConfigurationSession() {
        return globalSession;
    }
    
    /**
     * Get maximum priority level.
     *
     * @return The maximum priority level used by the filter. Priority levels
     *         can range from 0 to maxPriority (inclusive)
     */
    public int getMaxPriorityLevel() {
        return maxPriorityLevel;
    }

    /**
     * Get the current queue size (number of requests put on queue) for a given
     * priority level.
     *
     * @param priorityLevel Priority level to get queue size for (should be
     *                      a value between 0 and getMaxPriorityLevel(),
     *                      inclusive)
     * @return The number of requests in queue with the given priority level
     */
    public int getQueueSizeForPriorityLevel(final int priorityLevel) {
        return _queues.get(priorityLevel).size();
    }

    /**
     * Get maximum number of request configuration parameter from global
     * configuration, if defined.
     *
     * @return number of accepted concurrent requests, or empty if not
     *         configured
     */
    private Optional<Integer> getMaxRequestsFromConfig() {
        return getOptionalPositiveIntegerFromConfig("QOS_MAX_REQUESTS");
    }

    /**
     * Get maximum priority level configuration parameter from global
     * configuration, if defined.
     *
     * @return number of accepted concurrent requests, or empty if not
     *         configured
     */
    private Optional<Integer> getMaxPriorityLevelFromConfig() {
        return getOptionalPositiveIntegerFromConfig("QOS_MAX_PRIORITY");
    }

    /**
     * Get status for filter enablement. Default to false if global configuration
     * parameter is not set (and when set to an invalid boolean value).
     * 
     * @return true if filter should be invoked on requests 
     */
    public boolean getFilterEnabled() {
        final String enabledString = getGlobalParam("QOS_FILTER_ENABLED");

        if (enabledString != null) {
            switch(enabledString.toLowerCase(Locale.ENGLISH)) {
                case "true":
                    return true;
                case "false":
                    return false;
                default:
                    LOG.error("Illegal value for QOS_FILTER_ENABLED: " +
                              enabledString + ", default to disabled");
                    return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Gets the value of a global configuration parameter, if defined.
     *
     * @param property to get value of
     * @return the value, or empty if the property is not set
     */
    private Optional<Integer> getOptionalPositiveIntegerFromConfig(final String property) {
        final String valueString = getGlobalParam(property);

        if (valueString != null) {
            try {
                final int value = Integer.parseInt(valueString);

                if (value < 1) {
                    LOG.error(property + " must be a positive value");
                    return Optional.empty();
                }

                return Optional.of(value);
            } catch (NumberFormatException ex) {
                LOG.error("Illegal value for " + property + ": " + valueString +
                          ", using default value");
                return Optional.empty();
            }
        } else {
            return Optional.empty();
        }
    }

    /**
     * Helper method to populate the priority mapping.
     *
     * @param property String value of the priorty configuration value,
     *                 should be of the form ID1:prio1,ID2:prio2,...
     * @return a newly created priority map, mapping defined worker IDs to
     *         priority level. Note: this does not include the fallback
     *         to default level (0) for unassigned workers
     * @throws IllegalArgumentException 
     */
    private Map<Integer, Integer> createPriorityMap(final String property)
        throws IllegalArgumentException {
        final Map<Integer, Integer> newWorkerPriorities = new HashMap<>();
        final String maxPrioString = globalPropertyCache.get("QOS_MAX_PRIORITY");
        final int maxPrio =
                maxPrioString != null ? Integer.parseInt(maxPrioString) :
                                        __DEFAULT_MAX_PRIORITY;

        for (final String part : property.split(",")) {
            final String[] splitPart = part.split(":");

            if (splitPart.length != 2) {
                throw new IllegalArgumentException("Malformed QOS_PRIORITIES property: " +
                                                   property);
            }

            try {
                final int workerId = Integer.parseInt(splitPart[0].trim());
                final int priority = Integer.parseInt(splitPart[1].trim());

                if (priority < 0) {
                    throw new IllegalArgumentException("A priority can not be negative");
                } else if (priority > maxPrio) {
                    throw new IllegalArgumentException("A priority can not be higher than the maximum value");
                } else {
                    newWorkerPriorities.put(workerId, priority);
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Malformed QOS_PRIORITIES property: " +
                                                   property);
            }
        }

        return newWorkerPriorities;
    }

    /**
     * Create initial lists for queues and listeners.
     *
     * @param maxPriority The maximum number of priority levels to use
     */
    private void createQueuesAndListeners(final int maxPriority) {
        _queues = new ArrayList<>(maxPriority + 1);
        _listeners = new ArrayList<>(maxPriority + 1);
        maxPriorityLevel = maxPriority;
        for (int p = 0; p <= maxPriority; ++p)
        {
            _queues.add(p, new ConcurrentLinkedQueue<>());
            _listeners.add(p, new QoSAsyncListener(p, this));
        }
    }

    /**
     * Resize priority queues and listeners list for a new max priority level.
     * Just increase the size if needed, keep the old size if a lower max
     * prio level is set to avoid having to deal with resizing down and
     * potential race condition-like issues with remaining requests at higher
     * levels.
     * 
     * @param newMaxPriority New maximum level to use
     */
    private void resizeQueuesAndListenersIfNeeded(final int newMaxPriority) {
        _queues.ensureCapacity(newMaxPriority);
        _listeners.ensureCapacity(newMaxPriority);
        for (int p = maxPriorityLevel; p <= newMaxPriority; p++) {
            _queues.add(p, new ConcurrentLinkedQueue<>());
            _listeners.add(p, new QoSAsyncListener(p, this));
        }
        maxPriorityLevel = newMaxPriority;
    }

    /**
     * Implementation of doFilter from the Filter interface.
     * When this web filter is enabled, requests will be handled by the
     * internal implementation allowing a configureable maximum number
     * of concurrent ongoing requests directly, and putting additional
     * requests in priority queues based on the worker->priority mapping.
     * In case it is disabled, the request will be passed on to the rest
     * of filter chain.
     *
     * @param request Servlet request
     * @param response Servlet response
     * @param chain Filter chain defined by the application server, which
     *              this fiilter is part of
     * @throws IOException if an I/O error occurs during this filter's
     *                     processing of the request
     * @throws ServletException if the processing fails for any other reason
     */
    @Override
    public void doFilter(final ServletRequest request,
                         final ServletResponse response,
                         final FilterChain chain)
        throws IOException, ServletException {
        final boolean enabled = getFilterEnabled();

        /* if filter is disabled, just act like a pass-through to the rest of
         * the filter chain
         */
        if (!enabled) {
            chain.doFilter(request, response);
        } else {
            doFilterWithPriorities(request, response, chain);
        }
    }

    /**
     * Process request with queueing based on configured priorities.
     * 
     * @param request servlet request
     * @param response servlet response
     * @param chain filter chain
     * @throws IOException if an I/O error occurs during this filter's
     *                     processing of the request
     * @throws ServletException if the processing fails for any other reason
     */
    private void doFilterWithPriorities(final ServletRequest request,
                                        final ServletResponse response,
                                        final FilterChain chain)
            throws IOException, ServletException {
        boolean accepted = false;
        final Optional<Integer> maxRequestsConfig = getMaxRequestsFromConfig();
        final int maxRequests = maxRequestsConfig.orElse(__DEFAULT_PASSES);

        if (maxRequests != _maxRequests) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Got new value for max requests: " + maxRequests);
            }

            _passes = new Semaphore(maxRequests, true);
            _maxRequests = maxRequests;
        }

        final Optional<Integer> maxPrioConfig = getMaxPriorityLevelFromConfig();
        final int maxPrio = maxPrioConfig.orElse(__DEFAULT_MAX_PRIORITY);

        if (maxPrio != maxPriorityLevel) {
            resizeQueuesAndListenersIfNeeded(maxPrio);
        }

        try
        {
            Boolean suspended = (Boolean)request.getAttribute(_suspended);
            if (suspended == null)
            {
                accepted = _passes.tryAcquire(getWaitMs(), TimeUnit.MILLISECONDS);
                if (accepted)
                {
                    request.setAttribute(_suspended, Boolean.FALSE);
                    if (LOG.isDebugEnabled())
                        LOG.debug("Accepted " + request);
                }
                else
                {
                    request.setAttribute(_suspended, Boolean.TRUE);
                    int priority = getPriority(request, workerPriorities);
                    AsyncContext asyncContext = request.startAsync();
                    long suspendMs = getSuspendMs();
                    if (suspendMs > 0)
                        asyncContext.setTimeout(suspendMs);
                    asyncContext.addListener(_listeners.get(priority));
                    _queues.get(priority).add(asyncContext);
                    if (LOG.isDebugEnabled())
                        LOG.debug("Suspended " + request);
                    request.setAttribute(QOS_PRIORITY_ATTRIBUTE, priority);
                    return;
                }
            }
            else
            {
                if (suspended)
                {
                    request.setAttribute(_suspended, Boolean.FALSE);
                    Boolean resumed = (Boolean)request.getAttribute(_resumed);
                    if (Boolean.TRUE.equals(resumed))
                    {
                        _passes.acquire();
                        accepted = true;
                        if (LOG.isDebugEnabled())
                            LOG.debug("Resumed " + request);
                    }
                    else
                    {
                        // Timeout! try 1 more time.
                        accepted = _passes.tryAcquire(getWaitMs(), TimeUnit.MILLISECONDS);
                        if (LOG.isDebugEnabled())
                            LOG.debug("Timeout " + request);
                    }
                }
                else
                {
                    // Pass through resume of previously accepted request.
                    _passes.acquire();
                    accepted = true;
                    if (LOG.isDebugEnabled())
                        LOG.debug("Passthrough " + request);
                }
            }

            if (accepted)
            {
                chain.doFilter(request, response);
            }
            else
            {
                if (LOG.isDebugEnabled())
                    LOG.debug("Rejected " + request);
                ((HttpServletResponse)response).sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            }
        }
        catch (InterruptedException e)
        {
            ((HttpServletResponse)response).sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
        finally
        {
            if (accepted)
            {
                _passes.release();

                processQueues();
            }
        }
    }
    
    protected final void processQueues() {
        for (int p = _queues.size() - 1; p >= 0; --p)
        {
            AsyncContext asyncContext = _queues.get(p).poll();
            if (asyncContext != null)
            {
                ServletRequest candidate = asyncContext.getRequest();
                Boolean suspended = (Boolean)candidate.getAttribute(_suspended);
                if (Boolean.TRUE.equals(suspended))
                {
                    try
                    {  
                        candidate.setAttribute(_resumed, Boolean.TRUE);
                        asyncContext.dispatch();
                        break;
                    }
                    catch (IllegalStateException x)
                    {
                        LOG.warn(x);
                    }
                }
            }
        }
    }

    /**
     * Computes the request priority.
     *
     * @param request the incoming request
     * @param workerPriorities mapping of worker IDs to priority levels
     * @return the computed request priority
     */
    protected int getPriority(ServletRequest request,
                              Map<Integer, Integer> workerPriorities)
    {
        final HttpServletRequest baseRequest = (HttpServletRequest)request;
        final String servletPath = baseRequest.getServletPath();

        if ("/worker".equals(servletPath)) {
            int workerId;
            final String workerURIStart =
                baseRequest.getServletContext().getContextPath() + "/worker/";
            final String workerName = ServletUtils.parseWorkerName(baseRequest,
                                                                   workerURIStart);
            
            try {
                workerId = workerSession.getWorkerId(workerName);
            } catch (InvalidWorkerIdException ex) {
                LOG.error("Trying to get priority for a non-existing worker");
                return 0;
            }

            final Integer configuredPriority = workerPriorities.get(workerId);

            if (configuredPriority != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Returning priotity for worker: " + workerId +
                              ": " + configuredPriority);
                }
                return configuredPriority;
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Priority not configured for worker: " + workerId +
                              ", using default (0)");
                }
                return 0;
            }
        } else if ("/adminweb".equals(servletPath)) {
            // always prioritize requests to the admin web interfaces at highest prio
            return maxPriorityLevel;
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Not a /worker or /adminweb request, using default prio (0)");
            }
            return 0;
        }
    }

    @Override
    public void destroy()
    {
    }

    /**
     * Get the (short) amount of time (in milliseconds) that the filter would wait
     * for the semaphore to become available before suspending a request.
     *
     * @return wait time (in milliseconds)
     */
    //J @ManagedAttribute("(short) amount of time filter will wait before suspending request (in ms)")
    public long getWaitMs()
    {
        return _waitMs;
    }

    /**
     * Get the amount of time (in milliseconds) that the filter would suspend
     * a request for while waiting for the semaphore to become available.
     *
     * @return suspend time (in milliseconds)
     */
    //J @ManagedAttribute("amount of time filter will suspend a request for while waiting for the semaphore to become available (in ms)")
    public long getSuspendMs()
    {
        return _suspendMs;
    }

    /**
     * Get the maximum number of requests allowed to be processed
     * at the same time.
     *
     * @return maximum number of requests
     */
    //J @ManagedAttribute("maximum number of requests to allow processing of at the same time")
    public int getMaxRequests()
    {
        return _maxRequests;
    }

    /**
     * Get the value of a global configuration value.
     *
     * @param param global param to get the value for
     * @return global config parameter value
     */
    String getGlobalParam(final String param) {
        if (globalPropertyCacheLastUpdated + CONFIG_CACHE_TIMEOUT * 1000 <
            System.currentTimeMillis()) {
            synchronized (globalPropertyCache) {
                recreateGlobalPropertyCache();
            }
        }
        
        return globalPropertyCache.get(param);
    }
}
