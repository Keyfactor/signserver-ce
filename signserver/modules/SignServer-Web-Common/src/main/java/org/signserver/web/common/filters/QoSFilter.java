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
package org.signserver.web.common.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.qos.AbstractStatistics;
import org.signserver.ejb.interfaces.GlobalConfigurationSession;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.web.common.ServletUtils;

import static org.signserver.common.GlobalConfiguration.SCOPE_GLOBAL;
import static org.signserver.web.common.filters.QoSFilterProperties.QOS_FILTER_ENABLED;
import static org.signserver.web.common.filters.QoSFilterProperties.QOS_PRIORITIES;
import static org.signserver.web.common.filters.QoSFilterProperties.QOS_MAX_REQUESTS;
import static org.signserver.web.common.filters.QoSFilterProperties.QOS_MAX_PRIORITY;
import static org.signserver.web.common.filters.QoSFilterProperties.QOS_CACHE_TTL_S;
import static org.signserver.web.common.filters.QoSFilterProperties.QOS_PRIORITY;

/**
 * An asynchronous filter implementing the priority queues.
 * <p>
 * This filter's pattern is ideal to prevent wasting threads waiting for slow/limited resources such as a JDBC
 * connection pool. It avoids the situation where all of a containers thread pool may be consumed blocking on such a
 * slow resource. By limiting the number of active threads, a smaller thread pool may be used as the threads are not
 * wasted waiting. Thus, more memory may be available for use by the active threads.
 * </p><p>
 * This filter limits the number of active requests to the number set by the "maxRequests". If more requests are
 * received, they are suspended and placed on priority queues. Priorities are determined by the
 * {@link #getPriorityFromPriorities(ServletRequest, Map)} method and are a value between 0 and the value given by the "maxPriority",
 * with higher values having higher priority. The operational values of "maxRequests" and "maxPriority" are defined in
 * the extension Filter class(es), otherwise, the corresponding default is used (see {@link #DEFAULT_MAX_REQUESTS} and
 * {@link #DEFAULT_MAX_PRIORITY}).
 * </p><p>
 * Furthermore, this filter uses a priority when resuming waiting requests. So that if a container is under load, and
 * there are many requests waiting for resources, more important requests are serviced first. For example, this filter
 * could be deployed with a maxRequest limit slightly smaller than the containers thread pool and a high priority
 * allocated to admin users. Thus, regardless of load, admin users would always be able to access the web application.
 * </p><p>
 * The maxRequest limit is policed by a {@link Semaphore} and the filter will wait a short while attempting to acquire
 * the semaphore. This wait is controlled by the "waitMs" {@link #INIT_PARAM_WAIT_MS} init parameter
 * (or default {@link #DEFAULT_WAIT_MS}) and allows the expense of a suspend to be avoided if the semaphore is shortly
 * available. If the semaphore cannot be obtained, the request will be suspended for the default suspend period of the
 * container or the valued set as the "suspendMs" {@link #INIT_PARAM_SUSPEND_MS} init parameter (or default
 * {@link #DEFAULT_SUSPEND_MS}).
 * </p><p>
 * The configuration is defined as Global Parameters:
 * <ul>
 *     <li>GLOB.QOS_FILTER_ENABLED: true (to enable filter), default false (disabled);</li>
 *     <li>GLOB.QOS_MAX_REQUESTS: maximum number of concurrent requests to be accepted before queueing requests based
 *     on priority</li>
 *     <li>GLOB.QOS_MAX_PRIORITY: maximum priority level to use;</li>
 *     <li>GLOB.QOS_CACHE_TTL_S: number of seconds to keep cache. <b>NOTE:</b> Please use reasonable TTL.</li>
 *     <li>GLOB.QOS_PRIORITIES: comma-separated list of workerID:priority pairs.
 *     An example: GLOB.QOS_PRIORITIES=1:1,2:2,3:5</li>
 * </ul>
 * </p>
 * @version $Id$
 */
@WebFilter(asyncSupported = true)
public class QoSFilter implements Filter {

    // Logger for this class
    private static final Logger LOG = Logger.getLogger(QoSFilter.class);

    /**
     * The default number of active requests to handle at a time.
     */
    public static final int DEFAULT_MAX_REQUESTS = 10;
    /**
     * The default level of maximal priority for a request.
     */
    public static final int DEFAULT_MAX_PRIORITY = 5;
    /**
     * Describes the default amount of milliseconds to wait attempting to acquire the semaphore.
     */
    public static final long DEFAULT_WAIT_MS = 50;
    /**
     * Describes the default amount of milliseconds to suspend the acquire of semaphore.
     * @see #INIT_PARAM_SUSPEND_MS
     */
    public static final long DEFAULT_SUSPEND_MS = -1;
    /**
     * Describes the default amount of seconds to keep cache of Global Configuration.
     */
    public static final int DEFAULT_CACHE_TTL_S = 10;
    /**
     * Describes the amount of milliseconds to wait attempting to acquire the semaphore. Represents the reference to
     * <init-param/> of an implementation Filter in the web.xml. If undefined the default value is used.
     * @see #DEFAULT_WAIT_MS
     */
    public static final String INIT_PARAM_WAIT_MS = "waitMs";
    /**
     * Describes the amount of milliseconds to suspend the acquire of semaphore. Represents the reference to
     * <init-param/> of an implementation Filter in the web.xml. If undefined the default value is used.
     * @see #DEFAULT_SUSPEND_MS
     */
    public static final String INIT_PARAM_SUSPEND_MS = "suspendMs";

    @EJB
    private GlobalConfigurationSessionLocal globalSession;
    @EJB
    private WorkerSessionLocal workerSession;

    private static final List<String> GLOBAL_PROPERTY_CACHE_KEYS = Arrays.asList(QOS_FILTER_ENABLED, QOS_MAX_REQUESTS, QOS_MAX_PRIORITY, QOS_PRIORITIES, QOS_CACHE_TTL_S);
    
    private static final String SUSPENDED_ID = "QoSFilter@" + Integer.toHexString(QoSFilter.class.hashCode()) + ".SUSPENDED";
    private static final String RESUMED_ID = "QoSFilter@" + Integer.toHexString(QoSFilter.class.hashCode()) + ".RESUMED";
    
    private final State state;
    
    private static class State {
        
        private static final State INSTANCE = new State();
        
        public static State getInstance() {
            return INSTANCE;
        }
        
        // cache for global property values
        
        private final Map<String, String> GLOBAL_PROPERTY_CACHE = new HashMap<>();
        private long globalPropertyCacheLastUpdated;

        // A map containing linked values: workerId -> priority
        private Map<Integer, Integer> workerPriorities;

        // Operational vars
        private volatile int maxRequests;
        private int maxPriorityLevel;
        private long waitMs;
        private long suspendMs;
        private long cacheTtlS = DEFAULT_CACHE_TTL_S;

        // Queues
        private volatile Semaphore passesSemaphore; // Volatile so each thread will see the same instance
        private final ArrayList<AsyncListener> listeners = new ArrayList<>(0);
        private final ArrayList<Queue<AsyncContext>> queues = new ArrayList<>(0);

        
        private final Object UPDATE_SEMAPHORE_LOCK = new Object(); // Lock for updating the semaphore
    }
    
    public QoSFilter() {
        this(true);
    }
    
    protected QoSFilter(boolean globalState) {
        this.state = globalState ? State.getInstance() : new State();
    }
    
    

    /**
     * Returns the maximum priority level. Priority levels can range from 0 to maxPriority (inclusive).
     *
     * @return The maximum priority level used by the filter.
     */
    public int getMaxPriorityLevel() {
        synchronized (state.GLOBAL_PROPERTY_CACHE) {
            return state.maxPriorityLevel;
        }
    }

    /**
     * Returns the queue size (number of requests in queue) for a given priority level.
     *
     * @param priorityLevel Priority level of the queue.
     * @return The number of requests in queue with the given priority level
     */
    public int getQueueSizeForPriorityLevel(final int priorityLevel) {
        synchronized (state.queues) {
            return state.queues.get(priorityLevel).size();
        }
    }
    
    public int getSemaphoreQueueLength() {
        return state.passesSemaphore.getQueueLength();
    }
    
    public int getSemaphoreAvailablePermits() {
        return state.passesSemaphore.availablePermits();
    }

    /**
     * Returns the amount of time (in milliseconds) that the filter would wait for the semaphore to become available
     * before suspending a request.
     *
     * @return the wait time (in milliseconds).
     */
    //J @ManagedAttribute("(short) amount of time filter will wait before suspending request (in ms)")
    public long getWaitMs() {
        synchronized (state.GLOBAL_PROPERTY_CACHE) {
            return state.waitMs;
        }
    }

    /**
     * Returns the amount of time (in milliseconds) that the filter would suspend a request for while waiting for the
     * semaphore to become available.
     *
     * @return the suspend time (in milliseconds).
     */
    //J @ManagedAttribute("amount of time filter will suspend a request for while waiting for the semaphore to become available (in ms)")
    public long getSuspendMs() {
        synchronized (state.GLOBAL_PROPERTY_CACHE) {
            return state.suspendMs;
        }
    }

    /**
     * Returns the maximum number of requests allowed to be processed at the same time.
     *
     * @return the maximum number of requests.
     */
    //J @ManagedAttribute("maximum number of requests to allow processing of at the same time")
    public int getMaxRequests() {
        return state.maxRequests;
    }

    /**
     * Returns the amount of seconds to keep cache.
     *
     * @return the amount of seconds to keep cache.
     */
    public long getCacheTtlS() {
        synchronized (state.GLOBAL_PROPERTY_CACHE) {
            return state.cacheTtlS;
        }
    }

    /**
     * Returns a flag for filter enablement. By default it is disabled (false), unless the global configuration has
     * "true" value for QOS_FILTER_ENABLED property.
     *
     * @return true if filter is enabled.
     */
    public boolean isFilterEnabled() {
        return getFilterEnabledBooleanFromString(getGlobalPropertyFromCache(QOS_FILTER_ENABLED));
    }

    @Override
    public void init(final FilterConfig filterConfig) {
        // Load cache
        synchronized (state.GLOBAL_PROPERTY_CACHE) {
            if (state.passesSemaphore == null) {
                //recreateGlobalPropertyCache();
                //
                int maxRequests = getMaxRequestsFromConfig();
                state.passesSemaphore = new Semaphore(maxRequests, true);
                state.maxRequests = maxRequests;
                //
                state.waitMs = getLongFromInitParameter(filterConfig, INIT_PARAM_WAIT_MS, DEFAULT_WAIT_MS);
                state.suspendMs = getLongFromInitParameter(filterConfig, INIT_PARAM_SUSPEND_MS, DEFAULT_SUSPEND_MS);
                // Create queues and listeners
                resizeQueuesAndListenersIfNeeded(getMaxPriorityLevelFromConfig());
            }
            
            // Set the statistics implementation if one is not already there
            AbstractStatistics.setDefaultInstanceIfUnset(new QoSStatistics(this));
        }
    }

    /**
     * Implementation of doFilter from the Filter interface. When this web filter is enabled, requests will be handled
     * by the internal implementation allowing a configurable maximum number of concurrent ongoing requests directly,
     * and putting additional requests in priority queues based on the worker->priority mapping. In case it is disabled,
     * the request will be passed on to the rest of filter chain.
     *
     * @param request Servlet request
     * @param response Servlet response
     * @param chain Filter chain defined by the application server, which this filter is part of
     * @throws IOException if an I/O error occurs during this filter's processing of the request
     * @throws ServletException if the processing fails for any other reason
     */
    @Override
    public void doFilter(
            final ServletRequest request, final ServletResponse response, final FilterChain chain
    ) throws IOException, ServletException {
        // if filter is disabled, just act like a pass-through to the rest of the filter chain
        if (isFilterEnabled()) {
            doFilterWithPriorities(request, response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {}

    /**
     * Re-create the global property cache and the worker-priority mapping.
     */
    protected void recreateGlobalPropertyCache() {
        // Clear cache
        state.GLOBAL_PROPERTY_CACHE.clear();
        if(isCacheOutdated()) {
            // Early detection of enabled/disabled do not load the rest cache values if disabled
            final boolean isDisabled = !getFilterEnabledBooleanFromString(getGlobalProperty(QOS_FILTER_ENABLED));
            if(isDisabled) {
                // update cache TS and return
                state.GLOBAL_PROPERTY_CACHE.put(QOS_FILTER_ENABLED, "false");
                state.globalPropertyCacheLastUpdated = System.currentTimeMillis();
                return;
            }
        }
        // Load cache
        for (String key : GLOBAL_PROPERTY_CACHE_KEYS) {
            final String value = getGlobalProperty(key);
            // Don't use NULL values
            if(StringUtils.isNotBlank(value)) {
                state.GLOBAL_PROPERTY_CACHE.put(key, value);
            }
        }
        // update cache TS
        state.globalPropertyCacheLastUpdated = System.currentTimeMillis();
        // Load cache TTL
        state.cacheTtlS = getCacheTtlInSeconds(getGlobalPropertyFromCache(QOS_CACHE_TTL_S));
        // Load priorities
        final String priorityMappingString = getGlobalPropertyFromCache(QOS_PRIORITIES);
        state.workerPriorities = new HashMap<>();
        if (priorityMappingString != null) {
            try {
                state.workerPriorities = createPriorityMap(priorityMappingString);
            } catch (IllegalArgumentException e) {
                LOG.error("Failed to create priorities: " + e.getMessage());
            }
        }
    }

    /**
     * Processes request with queueing based on configured priorities.
     *
     * @param request servlet request
     * @param response servlet response
     * @param chain filter chain
     * @throws IOException if an I/O error occurs during this filter's processing of the request
     * @throws ServletException if the processing fails for any other reason
     */
    protected void doFilterWithPriorities(
            final ServletRequest request, final ServletResponse response, final FilterChain chain
    ) throws IOException, ServletException {
        
        boolean accepted = false;

        final int maxRequests = getMaxRequestsFromConfig();
        if (maxRequests != state.maxRequests) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Got new value for max requests: " + maxRequests);
            }
            
            synchronized (state.UPDATE_SEMAPHORE_LOCK) {
                if (maxRequests != state.maxRequests) {
                    // Adjust permits in Semaphore
                    if (maxRequests > state.maxRequests) { // Release more permits
                        state.passesSemaphore.release(maxRequests - state.maxRequests);
                        state.maxRequests = maxRequests;
                    } else { // We need to remove permits
                        state.maxRequests--;
                        try {
                            state.passesSemaphore.acquire();
                        } catch (InterruptedException ex) {
                            LOG.error("Interrupted when removing permits from semaphore: " + ex.getMessage());
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Interrupted when removing permits from semaphore", ex);
                            }
                            ((HttpServletResponse)response).sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                        }
                    }
                }
            }
        }

        synchronized (state.GLOBAL_PROPERTY_CACHE) {
            final int maxPriorityLevel = getMaxPriorityLevelFromConfig();
            if (maxPriorityLevel != state.maxPriorityLevel) {
                resizeQueuesAndListenersIfNeeded(maxPriorityLevel);
            }
        }

        try {
            final Boolean suspended = (Boolean)request.getAttribute(SUSPENDED_ID);
            if (suspended == null) {
                accepted = state.passesSemaphore.tryAcquire(getWaitMs(), TimeUnit.MILLISECONDS);
                if (accepted) {
                    request.setAttribute(SUSPENDED_ID, Boolean.FALSE);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Accepted " + request);
                    }
                }
                else {
                    request.setAttribute(SUSPENDED_ID, Boolean.TRUE);
                    int priority = getPriorityFromPriorities(request, state.workerPriorities);
                    AsyncContext asyncContext = request.startAsync();
                    long suspendMs = getSuspendMs();
                    if (suspendMs > 0) {
                        asyncContext.setTimeout(suspendMs);
                    }
                    synchronized (state.listeners) {
                        asyncContext.addListener(state.listeners.get(priority));
                    }
                    synchronized (state.queues) {
                        state.queues.get(priority).add(asyncContext);
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Suspended " + request);
                    }
                    request.setAttribute(QOS_PRIORITY, priority);
                    return;
                }
            }
            else {
                if (suspended) {
                    request.setAttribute(SUSPENDED_ID, Boolean.FALSE);
                    Boolean resumed = (Boolean)request.getAttribute(RESUMED_ID);
                    if (Boolean.TRUE.equals(resumed)) {
                        state.passesSemaphore.acquire();
                        accepted = true;
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Resumed " + request);
                        }
                    }
                    else {
                        // Timeout! try 1 more time.
                        accepted = state.passesSemaphore.tryAcquire(getWaitMs(), TimeUnit.MILLISECONDS);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Timeout " + request);
                        }
                    }
                }
                else {
                    // Pass through resume of previously accepted request.
                    state.passesSemaphore.acquire();
                    accepted = true;
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Passthroughs " + request);
                    }
                }
            }

            if (accepted) {
                chain.doFilter(request, response);
            }
            else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Rejected " + request);
                }
                ((HttpServletResponse)response).sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            }
        }
        catch (InterruptedException ex) {
            LOG.error("Interrupted: " + ex.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Interrupted", ex);
            }
            ((HttpServletResponse)response).sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
        finally {
            if (accepted) {
                state.passesSemaphore.release();
                processQueues();
            }
        }
    }

    // Processes the queue in reverse order.
    protected final void processQueues() {
        synchronized (state.queues) {
            for (int p = state.queues.size() - 1; p >= 0; --p) {
                final AsyncContext asyncContext = state.queues.get(p).poll();
                if (asyncContext != null) {
                    final ServletRequest candidate = asyncContext.getRequest();
                    if ((Boolean)candidate.getAttribute(SUSPENDED_ID)) {
                        try {
                            candidate.setAttribute(RESUMED_ID, Boolean.TRUE);
                            asyncContext.dispatch();
                            break;
                        }
                        catch (IllegalStateException x) {
                            LOG.warn(x);
                        }
                    }
                }
            }
        }
    }

    /**
     * Returns the global session (can be overridden by tests to use a mocked session).
     *
     * @return the global configuration session
     */
    protected GlobalConfigurationSession getGlobalConfigurationSession() {
        return globalSession;
    }

    /**
     * Returns the value of a global configuration from cache.
     *
     * @param property property to get the value for.
     * @return global config property value from cache.
     */
    protected String getGlobalPropertyFromCache(final String property) {
        synchronized (state.GLOBAL_PROPERTY_CACHE) {
            if (isCacheOutdated()) {    
                recreateGlobalPropertyCache();
            }
            return state.GLOBAL_PROPERTY_CACHE.get(property);
        }
    }

    /**
     * Get the cache map size (simplify for testing).
     *
     * @return the cache map size.
     */
    protected int getCacheMapSize() {
        synchronized (state.GLOBAL_PROPERTY_CACHE) {
            return state.GLOBAL_PROPERTY_CACHE.size();
        }
    }

    /**
     * Computes the request priority.
     *
     * @param request the incoming request
     * @param workerPriorities mapping of worker IDs to priority levels
     * @return the computed request priority
     */
    private int getPriorityFromPriorities(final ServletRequest request, final Map<Integer, Integer> workerPriorities) {
        final HttpServletRequest httpRequest = (HttpServletRequest)request;
        final String servletPath = httpRequest.getServletPath();
        int workerId;
        if ("/worker".equals(servletPath)) {
            final String workerURIStart = httpRequest.getServletContext().getContextPath() + "/worker/";
            final String workerName = ServletUtils.parseWorkerName(httpRequest, workerURIStart);
            //
            try {
                workerId = workerSession.getWorkerId(workerName);
            } catch (InvalidWorkerIdException ex) {
                LOG.error("Trying to get priority for a non-existing worker");
                return 0;
            }
            return getPriorityFromPriorities(workerId, workerPriorities);
        } else if ("/adminweb".equals(servletPath)) {
            // always prioritize requests to the admin web interfaces at highest priority
            synchronized (state.GLOBAL_PROPERTY_CACHE) {
                return state.maxPriorityLevel;
            }
        } else if("/PriorityClientWS".equals(servletPath)) {
            // always prioritize requests to the High Priority ClientWS
            synchronized (state.GLOBAL_PROPERTY_CACHE) {
                return state.maxPriorityLevel;
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Not a /worker or /adminweb request, using default priority (0)");
            }
            return 0;
        }
    }

    /**
     * Resizes the priority queues and listeners list for a new max priority level. Just increase the size if needed,
     * keep the old size if a lower max priority level is set to avoid having to deal with resizing down and potential
     * race condition-like issues with remaining requests at higher levels.
     *
     * @param newMaxPriority New maximum level to use
     */
    private void resizeQueuesAndListenersIfNeeded(final int newMaxPriority) {
        synchronized (state.queues) {
            synchronized (state.listeners) {
                state.queues.ensureCapacity(newMaxPriority);
                state.listeners.ensureCapacity(newMaxPriority);
                for (int p = state.maxPriorityLevel; p <= newMaxPriority; p++) {
                    state.queues.add(p, new ConcurrentLinkedQueue<>());
                    state.listeners.add(p, new AsyncPriorityQueuesListener(p, this));
                }
                state.maxPriorityLevel = newMaxPriority;
            }
        }
    }

    // Returns a global property (with scope GLOB) from the global configuration session.
    // NOTE: Read values from cache if possible.
    private String getGlobalProperty(final String property) {
        return getGlobalConfigurationSession().getGlobalConfiguration().getProperty(SCOPE_GLOBAL, property);
    }

    // Returns a maximum number of request from global configuration, {@link #DEFAULT_MAX_REQUESTS} otherwise.
    private int getMaxRequestsFromConfig() {
        return getPositiveIntFromConfig(QOS_MAX_REQUESTS, DEFAULT_MAX_REQUESTS);
    }

    // Returns a maximum priority level from global configuration, {@link #DEFAULT_MAX_PRIORITY} otherwise.
    private int getMaxPriorityLevelFromConfig() {
        return getPositiveIntFromConfig(QOS_MAX_PRIORITY, DEFAULT_MAX_PRIORITY);
    }

    // Returns the value of a global configuration parameter, if defined, or falls back to default value, if a value
    // cannot be read or less than 1.
    private int getPositiveIntFromConfig(final String property, final int defaultValue) {
        final String valueString = getGlobalPropertyFromCache(property);
        if (valueString != null) {
            try {
                final int value = Integer.parseInt(valueString);
                if (value < 1) {
                    LOG.error(property + " must have a positive value, using default value.");
                    return defaultValue;
                }
                return value;
            } catch (NumberFormatException ex) {
                LOG.error("Illegal value (" + valueString + ") for " + property + ", using default value.");
            }
        }
        return defaultValue;
    }

    // Returns the value of a global configuration parameter, if defined, or falls back to default value
    // DEFAULT_CACHE_TTL_S, if a value cannot be read or less than 1.
    private long getCacheTtlInSeconds(final String valueString) {
        if(valueString != null) {
            try {
                final long value = Long.parseLong(valueString);
                if(value < 1) {
                    LOG.error(QOS_CACHE_TTL_S + " must have a positive value, using default value.");
                    return DEFAULT_CACHE_TTL_S;
                }
                return value;
            }
            catch (NumberFormatException ex) {
                LOG.error("Illegal value (" + valueString + ") for " + QOS_CACHE_TTL_S + ", using default value.");
            }
        }
        return DEFAULT_CACHE_TTL_S;
    }

    // Returns a boolean from string, assumes the source of value is property
    private boolean getFilterEnabledBooleanFromString(final String valueString) {
        if (valueString != null) {
            switch(valueString.toLowerCase(Locale.ENGLISH)) {
                case "true":
                    return true;
                case "false":
                    return false;
                default:
                    LOG.error("Illegal value (" + valueString + ") for " + QOS_FILTER_ENABLED + ".");
                    return false;
            }
        }
        return false;
    }

    private boolean isCacheOutdated() {
        return state.globalPropertyCacheLastUpdated + getCacheTtlS() * 1000 < System.currentTimeMillis();
    }

    /**
     * Helper method to populate the priority mapping.
     *
     * @param property String value of the priority configuration value, should be of the form ID1:prio1,ID2:prio2,...
     * @return a newly created priority map, mapping defined worker IDs to priority level. Note: this does not include
     *         the fallback to default level (0) for unassigned workers
     * @throws IllegalArgumentException In case of malformed priorities string.
     */
    private Map<Integer, Integer> createPriorityMap(final String property) throws IllegalArgumentException {
        final Map<Integer, Integer> newWorkerPriorities = new HashMap<>();
        final int maxPriorityLevel = getMaxPriorityLevelFromConfig();

        for (final String part : property.split(",")) {
            final String[] splitPart = part.split(":");
            if (splitPart.length != 2) {
                throw new IllegalArgumentException("Malformed " + QOS_PRIORITIES + " property: " + property);
            }
            try {
                final int workerId = Integer.parseInt(splitPart[0].trim());
                final int priority = Integer.parseInt(splitPart[1].trim());
                if (priority < 0) {
                    throw new IllegalArgumentException("A priority can not be negative");
                } else if (priority > maxPriorityLevel) {
                    throw new IllegalArgumentException("A priority can not be higher than the maximum value");
                } else {
                    newWorkerPriorities.put(workerId, priority);
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Malformed " + QOS_PRIORITIES + " property: " + property);
            }
        }
        return newWorkerPriorities;
    }

    // Returns a long value of corresponding <init-param/> block or falls back to default value.
    private long getLongFromInitParameter(
            final FilterConfig filterConfig, final String initParamKey, final long defaultValue
    ) {
        final String initParamValue = filterConfig.getInitParameter(initParamKey);
        if (initParamValue != null) {
            try {
                return Long.parseLong(initParamValue);
            }
            catch (NumberFormatException ex) {
                LOG.error(
                        "Illegal value (" + initParamValue + ") for init parameter " + initParamKey +
                                ", using default value."
                );
            }
        }
        return defaultValue;
    }

    private int getPriorityFromPriorities(final int workerId, final Map<Integer, Integer> workerPriorities) {
        synchronized (state.GLOBAL_PROPERTY_CACHE) {
            final Integer configuredPriority = workerPriorities.get(workerId);
            if (configuredPriority != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Returning priority for worker: " + workerId + ": " + configuredPriority);
                }
                return configuredPriority;
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Priority not configured for worker: " + workerId + ", using default (0)");
                }
                return 0;
            }
        }
    }

    public void removeFromQueue(AsyncContext asyncContext, int priority) {
        synchronized (state.queues) {
            state.queues.get(priority).remove(asyncContext);
        }
    }
}
