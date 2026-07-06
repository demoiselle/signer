package org.demoiselle.signer.core.extension;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
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
import java.util.List;

public class AuthorityKeyIdentifierTest {

    @BeforeClass
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGetAuthorityKeyIdentifier() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(2048);
        KeyPair pair = kpGen.generateKeyPair();

        X500Name issuerName = new X500Name("CN=Mock CA");
        X500Name subjectName = new X500Name("CN=Test User");
        
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 10000);
        Date notAfter = new Date(System.currentTimeMillis() + 100000);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName, serial, notBefore, notAfter, subjectName, pair.getPublic()
        );

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Add Authority Key Identifier
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        AuthorityKeyIdentifier aki = extUtils.createAuthorityKeyIdentifier(pair.getPublic());
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);

        // Add Subject Key Identifier
        SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(pair.getPublic());
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);

        // Add Authority Info Access (AIA)
        AccessDescription accessDescription = new AccessDescription(
                AccessDescription.id_ad_ocsp,
                new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.com")
        );
        AuthorityInformationAccess aia = new AuthorityInformationAccess(accessDescription);
        certBuilder.addExtension(Extension.authorityInfoAccess, false, aia);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(pair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        BasicCertificate basicCertificate = new BasicCertificate(cert);
        
        // 1. Test Authority Key Identifier
        String certAuthorityKeyIdentifier = basicCertificate.getAuthorityKeyIdentifier();
        System.out.println("Authority Key Identifier: " + certAuthorityKeyIdentifier);
        Assert.assertNotNull("Authority Key Identifier should not be null", certAuthorityKeyIdentifier);
        Assert.assertTrue("Authority Key Identifier should have content", certAuthorityKeyIdentifier.length() > 0);

        // 2. Test Subject Key Identifier
        String certSubjectKeyIdentifier = basicCertificate.getSubjectKeyIdentifier();
        System.out.println("Subject Key Identifier: " + certSubjectKeyIdentifier);
        Assert.assertNotNull("Subject Key Identifier should not be null", certSubjectKeyIdentifier);
        Assert.assertTrue("Subject Key Identifier should have content", certSubjectKeyIdentifier.length() > 0);

        // 3. Test Authority Info Access (AIA)
        List<String> aiaList = basicCertificate.getAuthorityInfoAccess();
        System.out.println("AIA: " + aiaList);
        Assert.assertNotNull("AIA list should not be null", aiaList);
        Assert.assertFalse("AIA list should not be empty", aiaList.isEmpty());
        Assert.assertEquals("http://ocsp.example.com", aiaList.get(0));
    }
}
