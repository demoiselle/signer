package org.demoiselle.signer.signer.examples;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

public class GenerateCerts {

	@SuppressWarnings("resource")
	public static void main(String[] args) {

		Authority authority = new Authority();

		try {

			KeyStore keyStore = CertificateHelper.createRootCertificate(authority, "PKCS12");

			new FileOutputStream(new File("/tmp/new_ca.cer"))
					.write(keyStore.getCertificate(authority.alias()).getEncoded());

			keyStore.store(new FileOutputStream("/tmp/new_ca.p12"), "changeit".toCharArray());

			KeyStore keyStore2 = CertificateHelper.createServerCertificate("localhost",
					new SubjectAlternativeNameHolder(), authority, keyStore.getCertificate(authority.alias()),
					(PrivateKey) keyStore.getKey(authority.alias(), "changeit".toCharArray()));

			keyStore2.store(new FileOutputStream("/tmp/new_cert_localhost.p12"), "changeit".toCharArray());

			new FileOutputStream(new File("/tmp/new_cert_localhost.cer"))
					.write(keyStore2.getCertificate(authority.alias()).getEncoded());

		} catch (Throwable e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
