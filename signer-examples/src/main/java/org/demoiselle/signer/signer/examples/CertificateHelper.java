/*
 * Demoiselle Framework
 * Copyright (C) 2021 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package org.demoiselle.signer.signer.examples;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

public final class CertificateHelper {

	// private static final Logger log = LoggerFactory.getLogger(CertificateHelper.class);

	public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static final String KEYGEN_ALGORITHM = "RSA";

	private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";

	private static final String SIGNATURE_ALGORITHM = "SHA1WithRSAEncryption";

	private static final int ROOT_KEY_SIZE = 1024;

	private static final int FAKE_KEY_SIZE = 1024;

	/**
	 * Current time minus 1 year, just in case software clock
	 * goes back due to time synchronization.
	 */
	private static final Date NOT_BEFORE = new Date(System.currentTimeMillis() - 86400000L * 365);

	/**
	 * The maximum possible value in X.509 specification: 9999-12-31 23:59:59,
	 * new Date(253402300799000L), but Apple iOS 8 fails with a certificate
	 * expiration date grater than Mon, 24 Jan 6084 02:07:59 GMT (issue #6).
	 * <p>
	 * Hundred years in the future from starting the proxy should be enough.
	 */
	private static final Date NOT_AFTER = new Date(System.currentTimeMillis() + 86400000L * 365 * 100);

	public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(KEYGEN_ALGORITHM/* , PROVIDER_NAME */);
		SecureRandom secureRandom = SecureRandom
			.getInstance(SECURE_RANDOM_ALGORITHM/* , PROVIDER_NAME */);
		generator.initialize(keySize, secureRandom);
		return generator.generateKeyPair();
	}

	public static KeyStore createRootCertificate(Authority authority, String keyStoreType)
		throws NoSuchAlgorithmException, IOException,
		OperatorCreationException, CertificateException, KeyStoreException {

		KeyPair keyPair = generateKeyPair(ROOT_KEY_SIZE);

		X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		nameBuilder.addRDN(BCStyle.CN, authority.commonName());
		nameBuilder.addRDN(BCStyle.O, authority.organization());
		nameBuilder.addRDN(BCStyle.OU, authority.organizationalUnitName());

		X500Name issuer = nameBuilder.build();
		BigInteger serial = BigInteger.valueOf(initRandomSerial());
		PublicKey pubKey = keyPair.getPublic();

		X509v3CertificateBuilder generator = new JcaX509v3CertificateBuilder(
			issuer, serial, NOT_BEFORE, NOT_AFTER, issuer, pubKey);

		generator.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(pubKey));
		generator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

		KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
			| KeyUsage.dataEncipherment | KeyUsage.cRLSign);
		generator.addExtension(Extension.keyUsage, false, usage);

		ASN1EncodableVector purposes = new ASN1EncodableVector();
		purposes.add(KeyPurposeId.id_kp_serverAuth);
		purposes.add(KeyPurposeId.id_kp_clientAuth);
		purposes.add(KeyPurposeId.anyExtendedKeyUsage);
		generator.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

		X509Certificate cert = signCertificate(generator, keyPair.getPrivate());

		KeyStore result = KeyStore.getInstance(keyStoreType/* , PROVIDER_NAME */);
		result.load(null, null);
		result.setKeyEntry(authority.alias(), keyPair.getPrivate(), authority.password(), new Certificate[]{cert});
		return result;
	}

	private static SubjectKeyIdentifier createSubjectKeyIdentifier(Key key) throws IOException {
		ByteArrayInputStream bIn = new ByteArrayInputStream(key.getEncoded());
		ASN1InputStream is = null;
		try {
			is = new ASN1InputStream(bIn);
			ASN1Sequence seq = (ASN1Sequence) is.readObject();
			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(seq);
			return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
		} finally {
			IOUtils.closeQuietly(is);
		}
	}

	public static KeyStore createServerCertificate(String commonName,
												   SubjectAlternativeNameHolder subjectAlternativeNames, Authority authority, Certificate caCert,
												   PrivateKey caPrivKey)
		throws NoSuchAlgorithmException, NoSuchProviderException, IOException, OperatorCreationException,
		CertificateException, InvalidKeyException, SignatureException, KeyStoreException {

		KeyPair keyPair = generateKeyPair(FAKE_KEY_SIZE);

		X500Name issuer = new X509CertificateHolder(caCert.getEncoded()).getSubject();
		BigInteger serial = BigInteger.valueOf(initRandomSerial());

		X500NameBuilder name = new X500NameBuilder(BCStyle.INSTANCE);
		name.addRDN(BCStyle.CN, commonName);
		name.addRDN(BCStyle.O, authority.certOrganisation());
		name.addRDN(BCStyle.OU, authority.certOrganizationalUnitName());
		X500Name subject = name.build();

		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, NOT_BEFORE, NOT_AFTER,
			subject, keyPair.getPublic());

		builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(keyPair.getPublic()));
		builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

		subjectAlternativeNames.fillInto(builder);

		X509Certificate cert = signCertificate(builder, caPrivKey);

		cert.checkValidity(new Date());
		cert.verify(caCert.getPublicKey());

		KeyStore result = KeyStore.getInstance("PKCS12"
			/* , PROVIDER_NAME */);
		result.load(null, null);
		Certificate[] chain = {cert, caCert};
		result.setKeyEntry(authority.alias(), keyPair.getPrivate(), authority.password(), chain);

		return result;
	}

	private static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder,
												   PrivateKey signedWithPrivateKey) throws OperatorCreationException, CertificateException {
		ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME)
			.build(signedWithPrivateKey);
		return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME)
			.getCertificate(certificateBuilder.build(signer));
	}

	public static TrustManager[] getTrustManagers(KeyStore keyStore)
		throws KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {
		String trustManAlg = TrustManagerFactory.getDefaultAlgorithm();
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(trustManAlg
			/* , PROVIDER_NAME */);
		tmf.init(keyStore);
		return tmf.getTrustManagers();
	}

	public static KeyManager[] getKeyManagers(KeyStore keyStore, Authority authority)
		throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, KeyStoreException {
		String keyManAlg = KeyManagerFactory.getDefaultAlgorithm();
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(keyManAlg
			/* , PROVIDER_NAME */);
		kmf.init(keyStore, authority.password());
		return kmf.getKeyManagers();
	}

	public static long initRandomSerial() {
		final Random rnd = new Random();
		rnd.setSeed(System.currentTimeMillis());
		// prevent browser certificate caches, cause of doubled serial numbers
		// using 48bit random number
		long sl = ((long) rnd.nextInt()) << 32 | (rnd.nextInt() & 0xFFFFFFFFL);
		// let reserve of 16 bit for increasing, serials have to be positive
		sl = sl & 0x0000FFFFFFFFFFFFL;
		return sl;
	}

}
