/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.msauthcode.signer;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import net.jsign.asn1.authenticode.AuthenticodeDigestCalculatorProvider;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcPeImageData;
import net.jsign.asn1.authenticode.SpcUuid;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.WritableData;
import org.signserver.module.cmssigner.CMSSigner;
import org.signserver.module.extendedcmssigner.ExtendedCMSSigner;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.utils.timestampers.MSExternalRFC3161Timestamper;
import org.signserver.utils.timestampers.MSInternalRFC3161Timestamper;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.module.msauthcode.common.MSIUtils;
import org.signserver.module.msauthcode.common.SpcSipInfo;

/**
 * Implementation of a CMS signer using the Authenticode format.
 * 
 * @author Marcus Lundblad
 * @author Markus Kilås
 * @version $Id$
 */
public class MSAuthCodeCMSSigner extends ExtendedCMSSigner {

    private MSAuthCodeOptions authCodeOptions;
    private Collection<String> configErrors;
    
    /** Request metadata parameters */
    private final String FILE_TYPE = "FILE_TYPE";
    
    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        // Configuration errors
        configErrors = new LinkedList<>();
        authCodeOptions = new MSAuthCodeOptions();
        authCodeOptions.parse(config, configErrors);
        
        // don't allow setting or overriding CONTENT_OID, as we hard-code it
        String s = config.getProperty(CMSSigner.CONTENT_OID_PROPERTY, DEFAULT_NULL);
        if (s != null) {
            configErrors.add("Specifying CONTENTOID is not supported");
        }
        
        s = config.getProperty(CMSSigner.ALLOW_CONTENTOID_OVERRIDE, Boolean.FALSE.toString());
        if (Boolean.TRUE.toString().equalsIgnoreCase(s)) {
            configErrors.add("Allowing overriding CONTENTOID is not supported");
        }
    }
    
    @Override
    protected void sign(final ICryptoInstance crypto,
                        final X509Certificate cert,
                        final List<Certificate> certs, final String sigAlg,
                        final RequestContext requestContext,
                        final ReadableData requestData,
                        final WritableData responseData,
                        final ASN1ObjectIdentifier contentOIDToUse)
            throws IllegalRequestException, OperatorCreationException,
                   CertificateEncodingException, CMSException, IOException {
        signAuthenticodeStyle(crypto, cert, certs, sigAlg, requestContext,
                              requestData, responseData);
    }

    private void signAuthenticodeStyle(final ICryptoInstance crypto,
                                       final X509Certificate cert,
                                       final List<Certificate> certs,
                                       final String sigAlg,
                                       final RequestContext requestContext,
                                       final ReadableData requestData,
                                       final WritableData responseData)
            throws OperatorCreationException, IOException, CMSException,
                   CertificateEncodingException, IllegalRequestException {
        final AuthenticodeSignedDataGenerator generator = new AuthenticodeSignedDataGenerator();

        final AuthenticodeDigestCalculatorProvider calcProvider =
                    new AuthenticodeDigestCalculatorProvider();
        
        // prepare the authenticated attributes
        final CMSAttributeTableGenerator attributeTableGenerator =
                new DefaultSignedAttributeTableGenerator(
                        MSAuthCodeUtils.createAuthenticatedAttributes(requestContext,
                                                                      authCodeOptions));
        // prepare the signerInfo with the extra authenticated attributes
        final JcaSignerInfoGeneratorBuilder sigBuilder =
                new JcaSignerInfoGeneratorBuilder(calcProvider);
        sigBuilder.setSignedAttributeGenerator(attributeTableGenerator);

        final ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).setProvider(crypto.getProvider()).build(crypto.getPrivateKey());        
        final AlgorithmIdentifier algorithmIdentifier = clientSideHelper.getClientSideHashAlgorithm(requestContext);

        generator.addSignerInfoGenerator(sigBuilder.build(contentSigner, cert));
        generator.addCertificates(new JcaCertStore(certs));
        
        try (final OutputStream responseOutputStream = responseData.getAsInMemoryOutputStream()) {
            final byte[] content = requestData.getAsByteArray();

            DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, content);
            SpcAttributeTypeAndOptionalValue data = createSpcAttribute(requestContext);
            SpcIndirectDataContent spcIndirectDataContent = new SpcIndirectDataContent(data, digestInfo);

            CMSSignedData signedData = generator.generate(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID, spcIndirectDataContent);
            if (extendsCMSData()) {
                try {
                    signedData = extendCMSData(signedData, requestContext);
                } catch (TimestampingException ex) {
                    throw new IOException("Unable to extend CMS", ex);
                }
            }

            responseOutputStream.write(signedData.getEncoded());
        }
    }
    
    private SpcAttributeTypeAndOptionalValue createSpcAttribute(final RequestContext requestContext) {
        final String fileType = RequestMetadata.getInstance(requestContext).get(FILE_TYPE);
        
        if (fileType == null || "PE".equalsIgnoreCase(fileType)) {
            return new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID,
                                                        new SpcPeImageData());
        } else if ("MSI".equalsIgnoreCase(fileType)) {
            final SpcSipInfo sipInfo = MSIUtils.createMSISpcSipInfo();
            return new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, sipInfo);
        } else if ("PS1".equalsIgnoreCase(fileType)) {
            final net.jsign.asn1.authenticode.SpcSipInfo sipInfo = new net.jsign.asn1.authenticode.SpcSipInfo(65536, new SpcUuid("1FCC3B60-594B-084E-B724-D2C6297EF351"));
            return new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, sipInfo);
        } else {
            throw new IllegalArgumentException("Unknown file type: " + fileType);
        }
    }

    @Override
    protected Timestamper createTimestamper(RequestContext context) {
        if (getTsaUrl() != null) {
            return new MSExternalRFC3161Timestamper(getTsaPolicyOid(),
                                                  getTsaUsername(),
                                                  getTsaPassword());
        } else {
            return new MSInternalRFC3161Timestamper(getTsaWorker(),
                                                  getTsaPolicyOid(),
                                                  getTsaUsername(),
                                                  getTsaPassword(),
                                                  getWorkerSession(context));
        }
    }

    @Override
    protected List<String> getFatalErrors(IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }
}
