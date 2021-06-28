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
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingException;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
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
import org.bouncycastle.asn1.DERNull;
import org.signserver.common.RequestMetadata;
import org.signserver.module.msauthcode.common.SpcSipInfo;

/**
 * Implementation of a CMS signer using the Authenticode format for APPX files.
 * 
 * @author Selwyn Oh
 * @version $Id: MSAuthCodeCMSSigner.java 10475 2019-03-08 11:00:57Z netmackan $
 */
public class AppxCMSSigner extends ExtendedCMSSigner {

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
        signAppxStyle(crypto, cert, certs, sigAlg, requestContext,
                              requestData, responseData);
    }

    private void signAppxStyle(final ICryptoInstance crypto,
                                       final X509Certificate cert,
                                       final List<Certificate> certs,
                                       final String sigAlg,
                                       final RequestContext requestContext,
                                       final ReadableData requestData,
                                       final WritableData responseData)
            throws OperatorCreationException, IOException, CMSException,
                   CertificateEncodingException, IllegalRequestException {
        
        // This signer expects APPX as file type
        final String fileType = RequestMetadata.getInstance(requestContext).get(FILE_TYPE);
        if (!StringUtils.isBlank(fileType) && !"APPX".equalsIgnoreCase(fileType)) {
            throw new IllegalRequestException("Unknown file type: " + fileType);
        }

        final byte[] content = requestData.getAsByteArray();
        final SpcSipInfo sipInfo = MSAuthCodeUtils.createAppxSpcSipInfo();
        final AlgorithmIdentifier algorithmIdentifier = clientSideHelper.getClientSideHashAlgorithm(requestContext);
        final AppxSpcIndirectDataContent idc2 = new AppxSpcIndirectDataContent(new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, sipInfo), new DigestInfo(new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(), DERNull.INSTANCE), content));
        final LegacyAuthenticodeDigestCalculatorProvider calcProvider =
                new LegacyAuthenticodeDigestCalculatorProvider(); // Note: Does not set a provider currently, if this causes an issue we might have to explicitly specify BC

        final AppxSignedDataGenerator generator
                = new AppxSignedDataGenerator();

        // prepare the authenticated attributes
        final CMSAttributeTableGenerator attributeTableGenerator =
                new AppxSignedAttributeTableGenerator(
                        MSAuthCodeUtils.createAuthenticatedAttributes(requestContext,
                                                                      authCodeOptions));
        
        // prepare the signerInfo with the extra authenticated attributes
        final JcaSignerInfoGeneratorBuilder sigBuilder =
                new JcaSignerInfoGeneratorBuilder(calcProvider);
        sigBuilder.setSignedAttributeGenerator(attributeTableGenerator);

        final ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).setProvider(crypto.getProvider()).build(crypto.getPrivateKey());
        generator.addSignerInfoGenerator(sigBuilder.build(contentSigner, (X509Certificate) cert));
        generator.addCertificates(new JcaCertStore(certs));
        
        try (final OutputStream responseOutputStream = responseData.getAsInMemoryOutputStream()) {
            
            CMSSignedData signedData = generator.generate(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID, idc2);
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
