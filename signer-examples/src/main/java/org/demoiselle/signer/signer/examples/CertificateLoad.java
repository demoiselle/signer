package org.demoiselle.signer.signer.examples;

import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.demoiselle.signer.core.CertificateManager;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateLoad {

	private static final Logger logger = LoggerFactory.getLogger(CertificateLoad.class);

	public static KeyStoreLoader keyStoreLoader;
	public static KeyStore keyStore;
	public static X509Certificate certificate;
	public static PrivateKey privateKey;
	public static char[] password = "caro84867944".toCharArray();
	public static Certificate[] certificateChain;

	public static void main(String[] args) {

		try {
			// Carrega a keystore (TOKEN)
			keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();

			keyStoreLoader.setCallbackHandler(new CallbackHandler() {
				public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
					for (Callback callback : callbacks)
						if (callback instanceof PasswordCallback)
							((PasswordCallback) callback).setPassword(password);
				}
			});

			keyStore = keyStoreLoader.getKeyStore();
			Enumeration<String> aliases = keyStore.aliases();

			while (aliases.hasMoreElements()) {

				String alias = aliases.nextElement();

				logger.info("============= Alias: " + alias + " =============");

				certificate = (X509Certificate) keyStore.getCertificate(alias);
				privateKey = (PrivateKey) keyStore.getKey(alias, null);
				certificateChain = keyStore.getCertificateChain(alias);

				try {
					CertificateManager certificateManager = new CertificateManager(certificate);
					CertICPBrasil cert = certificateManager.load(CertICPBrasil.class);

					logger.info("Nome: " + cert.getNome());
					logger.info("CPF: " + cert.getCpf());
				} catch (Exception e) {
					logger.error("Erro ao carregar o certificado (ICP Brasil) com alias [" + alias + "]", e);
				}

			}

		} catch (Throwable e) {

			e.printStackTrace();

		}

	}
}
