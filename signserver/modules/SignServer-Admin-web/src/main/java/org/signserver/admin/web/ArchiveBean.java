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
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.signserver.admin.common.query.QueryUtil;
import org.signserver.admin.common.query.ArchiveFields;
import org.signserver.admin.common.query.ArchiveColumn;
import org.signserver.admin.common.query.OperatorsPerColumnUtil;
import org.signserver.admin.common.query.QueryOperator;
import org.signserver.admin.common.query.QueryCondition;
import org.signserver.admin.common.query.QueryOrdering;
import org.signserver.common.ArchiveMetadata;
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
public class ArchiveBean {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(ArchiveBean.class);

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZ");

    private static final String DEFAULT_QUERY = "";

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private String[] queryStrings = new String[] { DEFAULT_QUERY };
    private final PaginationSupport pagination = new PaginationSupport();
    private List<WebArchiveEntry> entries;
    private String queryError;
    private List<QueryCondition> conditions;
    private String conditionToAddError;

    private QueryCondition conditionToAdd;
    private String conditionColumn;

    private String requestedSelected;
    private Map<String, Boolean> selectedIds;
    private static final List<SelectItem> COLUMN_FROM_NAME = new ArrayList<>();

    private static final Map<String, String> NAME_FROM_COLUMN = new HashMap<>();

    static {
        for (ArchiveColumn col : ArchiveColumn.values()) {
            String description = col.toString();
            NAME_FROM_COLUMN.put(col.getName(), description);
            COLUMN_FROM_NAME.add(new SelectItem(description, col.name()));
        }
    }

    /**
     * Creates a new instance of ArchiveBean.
     */
    public ArchiveBean() {
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
        FacesContext.getCurrentInstance().getExternalContext().redirect("archive.xhtml?q=" + StringUtils.join(createQueryStrings(conditions), "&q=") + "&fromIndex=" + (pagination.getFromIndex() + 1) + "&maxEntries=" + pagination.getMaxEntries());
    }

    public void firstAction() throws IOException {
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

    public List<WebArchiveEntry> getEntries() throws AdminNotAuthorizedException {
        if (entries == null) {
            queryError = null;
            final QueryOrdering ordering = new QueryOrdering();
            ordering.setOrder(QueryOrdering.Order.DESC);
            ordering.setColumn(ArchiveMetadata.TIME);

            Boolean moreAvailable = null;
            try {

                List<ArchiveMetadata> results = workerSessionBean.queryArchive(authBean.getAdminCertificate(),
                        pagination.getFromIndex(), pagination.getMaxEntries(),
                        getConditions(),
                        Collections.singletonList(ordering), false);
                if (results == null) {
                    entries = Collections.emptyList();
                } else {
                    entries = convert(results);
                }
                pagination.updateResults(entries.size(), moreAvailable);

            } catch (SignServerException ex) {
                queryError = ex.getMessage();
                LOG.error("Reload failed within the selected interval: " + ex.getMessage(), ex);
            }
        }
        return entries;
    }

    public String getQueryError() {
        return queryError;
    }

    private List<WebArchiveEntry> convert(List<ArchiveMetadata> entries) {
        final ArrayList<WebArchiveEntry> results = new ArrayList<>(entries.size());
        for (ArchiveMetadata entry : entries) {
            results.add(WebArchiveEntry.fromArchiveMetadata(entry));
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
                    Term t = QueryUtil.parseCriteria(queryString, ArchiveFields.ALLOWED_FIELDS, ArchiveFields.NO_ARG_OPS, Collections.<String>emptySet(), ArchiveFields.INT_FIELDS, ArchiveFields.DATE_FIELDS);
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
                            sb.append(" ").append(condition.getValue());
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
        if (column.equals(ArchiveColumn.TIME.getName())) {
            // prepopulate with time value
            Long timeValue = getTimeValue(value);
            value = FDF.format(timeValue) + " (" + timeValue + ")";
        } else if (column.equals(ArchiveColumn.TYPE.getName())) {
            value = ArchiveMetadata.getTypeName(Integer.parseInt(value));
        }
        return value;
    }

    public void addConditionAction() {
        final ArchiveColumn column = ArchiveColumn.valueOf(conditionColumn);

        final String value;
        if (column == ArchiveColumn.TIME) {
            // prepopulate with time value
            value = FDF.format(System.currentTimeMillis());
        } else {
            value = "";
        }

        conditionToAdd = new QueryCondition(column.getName(), RelationalOperator.EQ, value);
    }

    public List<SelectItem> getDefinedConditions() {
        List<SelectItem> result = new ArrayList<>();
        QueryOperator[] operatorsForColumn = OperatorsPerColumnUtil.getOperatorsForColumn(ArchiveColumn.valueOf(conditionColumn));
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
        final ArchiveColumn column = ArchiveColumn.valueOf(conditionColumn);

        if (column == ArchiveColumn.TIME) {
            // Convert from time to timestamp
            Long value = getTimeValue(conditionToAdd.getValue());
            if (value == null) {
                conditionToAddError = "Incorrect time value";
                return;
            } else {
                conditionToAdd.setValue(String.valueOf(value));
            }
        } else if (column == ArchiveColumn.TYPE) {
            try {
                conditionToAdd.setValue(column.translateConditionValue(conditionToAdd.getValue()));
            } catch (IllegalArgumentException ex) {
                conditionToAddError = ex.getLocalizedMessage();
                return;
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

    public String downloadSelectedAction() {
        final StringBuilder sb = new StringBuilder();
        sb.append("archive-download?faces-redirect=true&amp;uniqueIds=");
        boolean anySelected = false;
        for (WebArchiveEntry entry : entries) {
            Boolean selected = selectedIds.get(entry.getUniqueId());
            if (selected != null && selected) {
                sb.append(entry.getUniqueId()).append(",");
                anySelected = true;
            }
        }
        if (!anySelected) {
            return "";
        } else {
            return sb.toString();
        }
    }

    public String getRequestedSelected() {
        return requestedSelected;
    }

    public void setRequestedSelected(String requestedSelected) {
        this.requestedSelected = requestedSelected;
    }

    public Map<String, Boolean> getSelectedIds() {
        if (selectedIds == null) {
            selectedIds = new HashMap<>();
            if (requestedSelected != null) {
                String[] split = requestedSelected.split(",");
                for (String s : split) {
                    s = s.trim();
                    if (!s.isEmpty()) {
                        selectedIds.put(s, Boolean.TRUE);
                    }
                }
            }
        }
        return selectedIds;
    }
}
