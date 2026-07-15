package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.util.Store;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Integration test: CMS (PKCS#7 / CAdES) level sign and verify using ML-DSA-44.
 * This simulates the real-world usage where a document is signed in CMS format
 * (the same format used by ICP-Brasil CAdES signatures).
 */
public class MLDSACMSSignVerifyTest {

	private static final byte[] CONTENT = "Hello".getBytes();

	@BeforeClass
	public static void setup() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	/**
	 * Generates a self-signed X509 certificate using ML-DSA-44.
	 */
	private static X509Certificate generateSelfSignedCert(KeyPair keyPair) throws Exception {
		X500Name subject = new X500Name("CN=ML-DSA Test, O=Demoiselle Signer, C=BR");
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
		Date notAfter = new Date(System.currentTimeMillis() + 365L * 86400000L);

		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				subject, serial, notBefore, notAfter, subject, keyPair.getPublic());

		ContentSigner contentSigner = new JcaContentSignerBuilder("ML-DSA-44")
				.setProvider("BC")
				.build(keyPair.getPrivate());

		X509CertificateHolder certHolder = certBuilder.build(contentSigner);
		return new JcaX509CertificateConverter()
				.setProvider("BC")
				.getCertificate(certHolder);
	}

	@Test
	public void testCMSSignAndVerify_ML_DSA_44() throws Exception {
		// 1. Generate ML-DSA-44 key pair
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", "BC");
		KeyPair keyPair = kpg.generateKeyPair();

		// 2. Generate self-signed certificate
		X509Certificate cert = generateSelfSignedCert(keyPair);
		assertNotNull("Certificate should be generated", cert);

		// 3. Create CMS signed data (detached signature)
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		generator.addSignerInfoGenerator(
				new JcaSimpleSignerInfoGeneratorBuilder()
						.setProvider("BC")
						.build("ML-DSA-44", keyPair.getPrivate(), cert));

		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		certList.add(cert);
		generator.addCertificates(new JcaCertStore(certList));

		CMSTypedData cmsData = new CMSProcessableByteArray(CONTENT);
		CMSSignedData signedData = generator.generate(cmsData, true); // attached

		assertNotNull("CMS SignedData should not be null", signedData);
		byte[] encoded = signedData.getEncoded();
		assertNotNull("Encoded signature should not be null", encoded);
		assertTrue("Encoded signature should have content", encoded.length > 0);

		// 4. Verify the CMS signature
		CMSSignedData parsedSignedData = new CMSSignedData(encoded);
		SignerInformationStore signerInfoStore = parsedSignedData.getSignerInfos();
		Collection<SignerInformation> signers = signerInfoStore.getSigners();
		assertTrue("Should have at least one signer", signers.size() > 0);

		Store<?> certs = parsedSignedData.getCertificates();
		Iterator<SignerInformation> it = signers.iterator();
		boolean verified = false;

		while (it.hasNext()) {
			SignerInformation signerInfo = it.next();
			Collection<?> certCollection = certs.getMatches(signerInfo.getSID());
			X509CertificateHolder certHolder = (X509CertificateHolder) certCollection.iterator().next();

			SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
					.setProvider("BC")
					.build(certHolder);

			verified = signerInfo.verify(verifier);
			assertTrue("CMS signature verification should succeed", verified);
		}
		assertTrue("At least one signature should have been verified", verified);
	}

	@Test
	public void testCMSVerifyFailsWithTamperedContent() throws Exception {
		// Generate and sign
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", "BC");
		KeyPair keyPair = kpg.generateKeyPair();
		X509Certificate cert = generateSelfSignedCert(keyPair);

		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		generator.addSignerInfoGenerator(
				new JcaSimpleSignerInfoGeneratorBuilder()
						.setProvider("BC")
						.build("ML-DSA-44", keyPair.getPrivate(), cert));

		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		certList.add(cert);
		generator.addCertificates(new JcaCertStore(certList));

		// Sign with original content
		CMSTypedData cmsData = new CMSProcessableByteArray(CONTENT);
		CMSSignedData signedData = generator.generate(cmsData, false); // detached
		byte[] encoded = signedData.getEncoded();

		// Verify with tampered content — should fail
		byte[] tamperedContent = "Tampered".getBytes();
		CMSSignedData tamperedSignedData = new CMSSignedData(
				new CMSProcessableByteArray(tamperedContent), encoded);

		SignerInformationStore signerInfoStore = tamperedSignedData.getSignerInfos();
		Store<?> certs = tamperedSignedData.getCertificates();

		for (SignerInformation signerInfo : signerInfoStore.getSigners()) {
			Collection<?> certCollection = certs.getMatches(signerInfo.getSID());
			X509CertificateHolder certHolder = (X509CertificateHolder) certCollection.iterator().next();

			SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
					.setProvider("BC")
					.build(certHolder);

			try {
				signerInfo.verify(verifier);
				// If no exception, test fails
				assertTrue("CMS verification should FAIL with tampered content", false);
			} catch (CMSSignerDigestMismatchException e) {
				// Expected: BC throws this when digest doesn't match
				assertTrue("Tampered content correctly detected", true);
			}
		}
	}
}
