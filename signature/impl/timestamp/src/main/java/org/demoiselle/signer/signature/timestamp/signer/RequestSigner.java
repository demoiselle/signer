package org.demoiselle.signer.signature.timestamp.signer;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class RequestSigner {

    private static final Logger logger = LoggerFactory.getLogger(RequestSigner.class);

    /**
     * Realiza a assinatura de uma requisicao de carimbo de tempo
     *
     * @param privateKey
     * @param certificates
     * @param request
     * @return A requisicao assinada
     */
    public byte[] signRequest(PrivateKey privateKey, Certificate[] certificates, byte[] request) {
        try {
            logger.info("Efetuando a assinatura da requisicao");
            Security.addProvider(new BouncyCastleProvider());

            X509Certificate signCert = (X509Certificate) certificates[0];
            List<X509Certificate> certList = new ArrayList<>();
            certList.add(signCert);

            // setup the generator
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA", privateKey, signCert);
            generator.addSignerInfoGenerator(signerInfoGenerator);

            Store certStore = new JcaCertStore(certList);
            generator.addCertificates(certStore);

//            Store crlStore = new JcaCRLStore(crlList);
//            generator.addCRLs(crlStore);
            // Create the signed data object
            CMSTypedData data = new CMSProcessableByteArray(request);
            CMSSignedData signed = generator.generate(data, true);
            return signed.getEncoded();

        } catch (CMSException | IOException | OperatorCreationException | CertificateEncodingException ex) {
            logger.info(ex.getMessage());
        }
        return null;
    }

}
