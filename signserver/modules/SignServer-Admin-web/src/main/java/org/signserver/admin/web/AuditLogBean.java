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
package org.signserver.admin.web;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.signserver.admin.common.query.QueryUtil;
import org.signserver.admin.common.query.AuditLogFields;
import org.signserver.admin.common.query.AuditLogColumn;
import org.signserver.admin.common.query.OperatorsPerColumnUtil;
import org.signserver.admin.common.query.QueryOperator;
import org.signserver.admin.common.query.QueryCondition;
import org.signserver.admin.common.query.QueryOrdering;
import org.signserver.common.SignServerException;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class AuditLogBean {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(AuditLogBean.class);

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZ");

    private static final String DEFAULT_QUERY = "eventType NEQ ACCESS_CONTROL";
    
    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private String[] queryStrings = new String[] { DEFAULT_QUERY };
    private final PaginationSupport pagination = new PaginationSupport();
    private List<WebAuditLogEntry> entries;
    private String queryError;
    private String queryErrorMain;
    private List<QueryCondition> conditions;
    private String conditionToAddError;

    private QueryCondition conditionToAdd;
    private String conditionColumn;

    private static final Map<String, String> NAME_FROM_COLUMN = new HashMap<>();
    private static final List<SelectItem> COLUMN_FROM_NAME = new ArrayList<>();

    static {
        for (AuditLogColumn col : AuditLogColumn.values()) {
            String description = col.getDescription() + " (" + col.getName() + ")";
            NAME_FROM_COLUMN.put(col.getName(), description);
            COLUMN_FROM_NAME.add(new SelectItem(description, col.name()));
        }
    }

    /**
     * Creates a new instance of AuditLogBean.
     */
    public AuditLogBean() {
    }

    public void init() throws AdminNotAuthorizedException {
        // Get queryStrings: There can be multiple "q" params.
        String[] q = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterValuesMap().get("q");
        if (q != null) {
            queryStrings = q;
        }

        // Do the query now
        getEntries();
    }
    
    public AuthenticationBean getAuthBean() {
        return authBean;
    }

    public void setAuthBean(AuthenticationBean authBean) {
        this.authBean = authBean;
    }

    public Integer getFromIndex() throws AdminNotAuthorizedException {
        return pagination.getFromIndex() + 1;
    }

    public void setFromIndex(Integer fromIndex) {
        pagination.setFromIndex(fromIndex - 1);
    }

    public void reloadAction() throws IOException {
        entries = null;
        FacesContext.getCurrentInstance().getExternalContext().redirect("auditlog.xhtml?q=" + StringUtils.join(createQueryStrings(conditions), "&q=") + "&fromIndex=" + (pagination.getFromIndex() + 1) + "&maxEntries=" + pagination.getMaxEntries());
    }

    public void firstAction() throws UnsupportedEncodingException, IOException {
        pagination.goToFirst();
        reloadAction();
    }

    public void previousAction() throws IOException {
        pagination.goBackwards();

        // Reload
        reloadAction();
    }

    public void nextAction() throws IOException {
        pagination.goForward();

        // Reload
        reloadAction();
    }

    public Integer getMaxEntries() {
        return pagination.getMaxEntries();
    }

    public void setMaxEntries(Integer numEntries) {
        pagination.setMaxEntries(numEntries);
    }

    public Integer getQueryingToIndex() throws AdminNotAuthorizedException {
        return pagination.getQueryingToIndex();
    }

    public boolean isEnableFirst() throws AdminNotAuthorizedException {
        return pagination.isEnableFirst();
    }

    public boolean isEnablePrevious() throws AdminNotAuthorizedException {
        return pagination.isEnablePrevious();
    }

    public boolean isEnableNext() throws AdminNotAuthorizedException {
        return pagination.isEnableNext();
    }

    public List<WebAuditLogEntry> getEntries() throws AdminNotAuthorizedException {
        if (entries == null) {
            queryError = null;
            QueryOrdering ordering = new QueryOrdering();
            ordering.setOrder(QueryOrdering.Order.DESC);
            ordering.setColumn(AuditRecordData.FIELD_TIMESTAMP);

            Boolean moreAvailable = null;
            try {

                List<? extends AuditLogEntry> results = workerSessionBean.queryAuditLog(authBean.getAdminCertificate(),
                        pagination.getFromIndex(), pagination.getMaxEntries(),
                        getConditions(),
                        Collections.singletonList(ordering));
                if (results == null) {
                    entries = Collections.emptyList();
                } else {
                    entries = convert(results);
                }
                pagination.updateResults(entries.size(), moreAvailable);

            } catch (javax.ejb.EJBTransactionRolledbackException ex) {
                queryError = ex.getMessage();
                queryErrorMain = AuditLogFields.ERR_DB_PROTECTION_FAILED;
                LOG.error(queryErrorMain + ex.getMessage());
            } catch (SignServerException | EJBException ex) {
                queryError = ex.getMessage();
                queryErrorMain = AuditLogFields.ERR_RELOAD_FAILED;
                LOG.error(queryErrorMain + ex.getMessage());
            }
        }
        return entries;
    }

    public String getQueryError() {
        return queryError;
    }
    
     public String getQueryErrorMain() {
        return queryErrorMain;
    }

    private List<WebAuditLogEntry> convert(List<? extends AuditLogEntry> entries) {
        final ArrayList<WebAuditLogEntry> results = new ArrayList<>(entries.size());
        for (AuditLogEntry entry : entries) {
            results.add(WebAuditLogEntry.fromAuditLogEntry(entry));
        }
        return results;
    }

    public List<QueryCondition> getConditions() {
        if (conditions == null) {
            conditions = parseQuery(queryStrings);
        }
        return conditions;
    }

    private List<QueryCondition> parseQuery(String[] queryStrings) {
        List<QueryCondition> results = new ArrayList<>(queryStrings.length);
        
        for (String queryString : queryStrings) {
            if (!queryString.trim().isEmpty()) {
                try {
                    Term t = QueryUtil.parseCriteria(queryString, AuditLogFields.ALLOWED_FIELDS, AuditLogFields.NO_ARG_OPS, Collections.<String>emptySet(), AuditLogFields.LONG_FIELDS, AuditLogFields.DATE_FIELDS);
                    results.add(new QueryCondition(t.getName(), t.getOperator(), t.getValue() == null ? null : String.valueOf(t.getValue())));
                } catch (IllegalArgumentException | ParseException ex) {
                    queryError = "One or more incorrect query conditions was dropped: " + ex.getMessage();
                }
            }
        }
        
        return results;
    }

    private static List<String> createQueryStrings(List<QueryCondition> conditions) {
        final List<String> results;
        if (conditions == null || conditions.isEmpty()) {
            results = Collections.singletonList(" "); // We need to support "q=" to query without the default "eventType NEQ ACCESS_CONTROL"
        } else {
            try {
                results = new ArrayList<>(conditions.size());
                for (QueryCondition condition : conditions) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(condition.getColumn()).append(" ").append(condition.getOperator());
                    if (condition.getValue() != null) {
                        sb.append(" ").append(condition.getValue()); // Should not use URLEncoder, that is taken care of by JSF, however we need to escape some stuff so it works with JSF?
                    }
                    results.add(URLEncoder.encode(sb.toString(), StandardCharsets.UTF_8.name()));
                }
            } catch (UnsupportedEncodingException ex) {
                throw new IllegalStateException(ex);
            }
        }
        return results;
    }

    public QueryCondition getConditionToAdd() {
        return conditionToAdd;
    }

    public Map<String, String> getNameFromColumn() {
        return NAME_FROM_COLUMN;
    }

    public List<SelectItem> getColumns() {
        return COLUMN_FROM_NAME;
    }

    public String getConditionColumn() {
        return conditionColumn;
    }

    public void setConditionColumn(String conditionColumn) {
        this.conditionColumn = conditionColumn;
    }

    public String nameFromCondition(RelationalOperator condition) {
        return QueryOperator.fromEnum(condition).getDescription();
    }

    public String nameFromValue(String value, String column) {
        if (column.equals(AuditLogColumn.TIMESTAMP.getName())) {
            // prepopulate with time value
            Long timeValue = getTimeValue(value);
            value = FDF.format(timeValue) + " (" + timeValue + ")";
        }
        return value;
    }

    public void addConditionAction() {
        final AuditLogColumn column = AuditLogColumn.valueOf(conditionColumn);

        final String value;
        if (column == AuditLogColumn.TIMESTAMP) {
            // prepopulate with time value
            value = FDF.format(System.currentTimeMillis());
        } else {
            value = "";
        }

        conditionToAdd = new QueryCondition(column.getName(), RelationalOperator.EQ, value);
    }

    public List<SelectItem> getDefinedConditions() {
        List<SelectItem> result = new ArrayList<>();
        QueryOperator[] operatorsForColumn = OperatorsPerColumnUtil.getOperatorsForColumn(AuditLogColumn.valueOf(conditionColumn));
        for (QueryOperator op : operatorsForColumn) {
            result.add(new SelectItem(op.getDescription(), op.getOperator().name()));
        }
        return result;
    }

    public void removeConditionToAddAction() {
        conditionToAdd = null;
        conditionColumn = null;
        conditionToAddError = null;
    }

    public void addConditionToAddAction() {
        final AuditLogColumn column = AuditLogColumn.valueOf(conditionColumn);

        if (column == AuditLogColumn.TIMESTAMP) {
            // Convert from time to timestamp
            Long value = getTimeValue(conditionToAdd.getValue());
            if (value == null) {
                conditionToAddError = "Incorrect time value";
                return;
            } else {
                conditionToAdd.setValue(String.valueOf(value));
            }
        }

        conditions.add(conditionToAdd);
        conditionToAdd = null;
        conditionColumn = null;
        conditionToAddError = null;
    }

    private static Long getTimeValue(String value) {
        Long result = null;
        try {
            result = Long.parseLong(value);
        } catch (NumberFormatException ex) {  // NOPMD
            try {
                result = ValidityDate.parseAsIso8601(value).getTime();
            } catch (ParseException ignored) { //NOPMD
            }
        }
        return result;
    }

    public String getConditionToAddError() {
        return conditionToAddError;
    }

    public void removeConditionAction(QueryCondition condition) {
        conditions.remove(condition);
    }

}
