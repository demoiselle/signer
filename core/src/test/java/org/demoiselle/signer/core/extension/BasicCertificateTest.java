package org.demoiselle.signer.core.extension;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

public class BasicCertificateTest {

    @BeforeClass
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private X509Certificate generateMockCertificate(String dn, String policyOid) throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(2048);
        KeyPair pair = kpGen.generateKeyPair();

        X500Name issuerName = new X500Name("CN=Mock CA");
        X500Name subjectName = new X500Name(dn);
        
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 10000);
        Date notAfter = new Date(System.currentTimeMillis() + 100000);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName, serial, notBefore, notAfter, subjectName, pair.getPublic()
        );

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        if (policyOid != null) {
            ASN1EncodableVector policyVec = new ASN1EncodableVector();
            policyVec.add(new ASN1ObjectIdentifier(policyOid));
            DERSequence policySequence = new DERSequence(policyVec);
            ASN1EncodableVector policiesVec = new ASN1EncodableVector();
            policiesVec.add(policySequence);
            DERSequence policiesSequence = new DERSequence(policiesVec);
            certBuilder.addExtension(Extension.certificatePolicies, false, policiesSequence);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(pair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    @Test
    public void testExtractionPFSN() throws Exception {
        // Novo Perfil Pessoa Fisica
        String cpf = "12345678901";
        // 2.5.4.5 is SN (SerialNumber)
        X509Certificate cert = generateMockCertificate("CN=Fulano da Silva, SERIALNUMBER=" + cpf, null);
        
        BasicCertificate bc = new BasicCertificate(cert);
        
        Assert.assertTrue(bc.hasCertificatePF());
        Assert.assertFalse(bc.hasCertificatePJ());
        
        ICPBRCertificatePF pf = bc.getICPBRCertificatePF();
        Assert.assertNotNull(pf);
        Assert.assertEquals(cpf, pf.getCPF());
    }

    @Test
    public void testExtractionPJSN() throws Exception {
        String cnpj = "12345678000199";
        X509Certificate cert = generateMockCertificate("CN=Empresa Teste, SERIALNUMBER=" + cnpj, null);
        
        BasicCertificate bc = new BasicCertificate(cert);
        
        Assert.assertTrue(bc.hasCertificatePJ());
        Assert.assertFalse(bc.hasCertificatePF());
        
        ICPBRCertificatePJ pj = bc.getICPBRCertificatePJ();
        Assert.assertNotNull(pj);
        Assert.assertEquals(cnpj, pj.getCNPJ());
    }

    @Test
    public void testExtractionSESN() throws Exception {
        String cnpj = "12345678000199";
        X509Certificate cert = generateMockCertificate(
            "CN=Empresa Teste, SERIALNUMBER=" + cnpj,
            "2.16.76.1.2.201"
        );
        
        BasicCertificate bc = new BasicCertificate(cert);
        
        Assert.assertTrue(bc.isSeloEletronico());
        Assert.assertTrue(bc.hasCertificateSE());
        Assert.assertFalse(bc.hasCertificatePJ());
        Assert.assertFalse(bc.hasCertificatePF());
        
        ICPBRCertificateSE se = bc.getICPBRCertificateSE();
        Assert.assertNotNull(se);
        Assert.assertEquals(cnpj, se.getCNPJ());
    }
}
