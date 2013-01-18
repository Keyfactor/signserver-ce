/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.cesecoreintegration;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.AuditLogExportReport;
import org.cesecore.audit.audit.AuditLogExporterException;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.AuditLogValidatorException;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedAuditorSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.query.QueryCriteria;

/**
 *
 * @author markus
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class NoIntegrityProtectedAuditorSessionBean implements IntegrityProtectedAuditorSessionLocal {

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public int deleteRows(AuthenticationToken token, Date timestamp, Properties properties) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported in NODB mode.");
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<? extends AuditLogEntry> selectAuditLogs(AuthenticationToken token, int startIndex, int max, QueryCriteria criteria, Properties properties) {
        throw new UnsupportedOperationException("Not supported in NODB mode.");
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public AuditLogExportReport exportAuditLogs(AuthenticationToken token, CryptoToken cryptoToken, Date timestamp, boolean deleteAfterExport, Map<String, Object> signatureDetails, Properties properties, Class<? extends AuditExporter> exporter) throws AuditLogExporterException {
        throw new UnsupportedOperationException("Not supported in NODB mode.");
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public AuditLogValidationReport verifyLogsIntegrity(AuthenticationToken token, Date date, Properties properties) throws AuditLogValidatorException {
        throw new UnsupportedOperationException("Not supported in NODB mode.");
    }
    
}
