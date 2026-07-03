package org.demoiselle.signer.core.extension;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
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
import java.util.ArrayList;
import java.util.List;

public class Resolution211Test {

    @BeforeClass
    public static void setUpClass() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private X509Certificate generateMockCertificate(String dn, String policyOid, List<ASN1Sequence> otherNames) throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(2048);
        KeyPair pair = kpGen.generateKeyPair();

        X500Name issuerName = new X500Name("CN=Mock CA");
        X500Name subjectName = new X500Name(dn);
        
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 10000);
        Date notAfter = new Date(System.currentTimeMillis() + 1000000000L); // Long validity

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

        if (otherNames != null && !otherNames.isEmpty()) {
            GeneralName[] gns = new GeneralName[otherNames.size()];
            for (int i = 0; i < otherNames.size(); i++) {
                gns[i] = new GeneralName(GeneralName.otherName, otherNames.get(i));
            }
            GeneralNames subjectAltNames = new GeneralNames(gns);
            certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(pair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    private ASN1Sequence createOtherName(String oid, ASN1Encodable value) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1ObjectIdentifier(oid));
        v.add(new DERTaggedObject(true, 0, value));
        return new DERSequence(v);
    }

    @Test
    public void testNewProfilePF() throws Exception {
        String cpf = "93274300500";
        String cnpjAR = "33683111000107";
        
        List<ASN1Sequence> otherNames = new ArrayList<ASN1Sequence>();
        // ICP-Brasil often uses OCTET STRING for these OIDs
        otherNames.add(createOtherName("2.16.76.1.4.5.1", new DEROctetString(cnpjAR.getBytes())));
        
        X509Certificate cert = generateMockCertificate(
            "CN=EVANDRO TESTE, SERIALNUMBER=" + cpf,
            "2.16.76.1.2.3", // A3
            otherNames
        );
        
        BasicCertificate bc = new BasicCertificate(cert);
        Assert.assertTrue("Deveria ser PF", bc.hasCertificatePF());
        Assert.assertEquals("CPF incorreto", cpf, bc.getICPBRCertificatePF().getCPF());

        Assert.assertEquals("Tipo incorreto", "A", bc.getCertificateType());
        Assert.assertEquals("Nível incorreto", "A3", bc.getCertificateLevel());
    }

    @Test
    public void testNewProfileSES() throws Exception {
        String cnpj = "00000000000191";
        X509Certificate cert = generateMockCertificate(
            "CN=EMPRESA TESTE, SERIALNUMBER=" + cnpj,
            "2.16.76.1.2.201", // SE-S
            null
        );
        
        BasicCertificate bc = new BasicCertificate(cert);
        Assert.assertTrue("Deveria ser SE", bc.hasCertificateSE());
        Assert.assertEquals("CNPJ incorreto", cnpj, bc.getICPBRCertificateSE().getCNPJ());
        Assert.assertEquals("Tipo incorreto", "SE", bc.getCertificateType());
        Assert.assertEquals("Nível incorreto", "SE-S", bc.getCertificateLevel());
    }

    @Test
    public void testNewProfileSEH() throws Exception {
        String cnpj = "00000000000191";
        X509Certificate cert = generateMockCertificate(
            "CN=EMPRESA TESTE, SERIALNUMBER=" + cnpj,
            "2.16.76.1.2.202", // SE-H
            null
        );
        
        BasicCertificate bc = new BasicCertificate(cert);
        Assert.assertTrue("Deveria ser SE", bc.hasCertificateSE());
        Assert.assertEquals("CNPJ incorreto", cnpj, bc.getICPBRCertificateSE().getCNPJ());
        Assert.assertEquals("Tipo incorreto", "SE", bc.getCertificateType());
        Assert.assertEquals("Nível incorreto", "SE-H", bc.getCertificateLevel());
    }

    @Test
    public void testNewProfileAES() throws Exception {
        X509Certificate cert = generateMockCertificate(
            "CN=APP TESTE",
            "2.16.76.1.2.203", // AE-S
            null
        );
        
        BasicCertificate bc = new BasicCertificate(cert);
        Assert.assertTrue("Deveria ser AE", bc.isAplicacaoEspecifica());
        Assert.assertEquals("Tipo incorreto", "AE", bc.getCertificateType());
        Assert.assertEquals("Nível incorreto", "AE-S", bc.getCertificateLevel());
    }

    @Test
    public void testNewProfileAEH() throws Exception {
        X509Certificate cert = generateMockCertificate(
            "CN=APP TESTE",
            "2.16.76.1.2.204", // AE-H
            null
        );
        
        BasicCertificate bc = new BasicCertificate(cert);
        Assert.assertTrue("Deveria ser AE", bc.isAplicacaoEspecifica());
        Assert.assertEquals("Tipo incorreto", "AE", bc.getCertificateType());
        Assert.assertEquals("Nível incorreto", "AE-H", bc.getCertificateLevel());
    }

    @Test
    public void testOldProfilePF() throws Exception {
        String cpf = "93274300500";
        // Mock OID 2.16.76.1.3.1 - PF Data (Birthdate=01011980, CPF, NIS, RG, Org)
        String pfData = "01011980" + cpf + "12345678901" + "123456789012345" + "SSP       ";
        
        List<ASN1Sequence> otherNames = new ArrayList<ASN1Sequence>();
        // Single wrap should be enough if OIDGeneric.getInstance(byte[]) is used correctly
        otherNames.add(createOtherName("2.16.76.1.3.1", new DEROctetString(pfData.getBytes())));
        
        X509Certificate cert = generateMockCertificate(
            "CN=EVANDRO VELHO",
            "2.16.76.1.2.3", // A3
            otherNames
        );
        
        BasicCertificate bc = new BasicCertificate(cert);
        Assert.assertTrue("Deveria ser PF", bc.hasCertificatePF());
        Assert.assertEquals("CPF incorreto", cpf, bc.getICPBRCertificatePF().getCPF());
    }

    @Test
    public void testOldProfilePJ() throws Exception {
        String cnpj = "00000000000191";
        // Mock OID 2.16.76.1.3.3 - CNPJ
        List<ASN1Sequence> otherNames = new ArrayList<ASN1Sequence>();
        otherNames.add(createOtherName("2.16.76.1.3.3", new DEROctetString(cnpj.getBytes())));
        
        X509Certificate cert = generateMockCertificate(
            "CN=EMPRESA VELHA",
            "2.16.76.1.3.7", // Policy for PJ in old profile
            otherNames
        );
        
        BasicCertificate bc = new BasicCertificate(cert);
        Assert.assertTrue("Deveria ser PJ", bc.hasCertificatePJ());
        Assert.assertEquals("CNPJ incorreto", cnpj, bc.getICPBRCertificatePJ().getCNPJ());
    }
}
