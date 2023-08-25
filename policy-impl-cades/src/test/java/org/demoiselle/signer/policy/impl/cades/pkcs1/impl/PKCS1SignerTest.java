package org.demoiselle.signer.policy.impl.cades.pkcs1.impl;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.Enumeration;

import org.apache.commons.codec.binary.Base64;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.core.keystore.loader.implementation.MSKeyStoreLoader;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.junit.Test;

public class PKCS1SignerTest {

	//@Test
	public void testDoSign() {
		try {

			System.out.println("******** TESTANDO COM ARQUIVO *****************");

			// INFORMAR o arquivo

			//
			// String fileDirName = "C:\\Users\\{usuario}\\arquivo_assinar";
			String fileDirName = "/";
			byte[] fileToSign = readContent(fileDirName);

			//fileToSign = Base64.decodeBase64("VGVzdGUgQXNzaW5hdHVyYQo=");

			// Para certificado NeoID e windows token
			KeyStore ks = getKeyStoreTokenBySigner();

			//// Para certificado em arquivo A1
			// KeyStore ks = getKeyStoreFileBySigner();

			// Keystore diferente para timestamp
			// KeyStore ksToTS = getKeyStoreStreamBySigner();

			// Para certificado token Linux
			// KeyStore ks = getKeyStoreToken();

			// Para certificados no so windows (mascapi)
			// KeyStore ks = getKeyStoreOnWindows();

			String alias = getAlias(ks);
			// String aliasToTs = getAlias(ksToTS);
			// char[] senhaTS = "senha".toCharArray();
			/* Parametrizando o objeto doSign */

			PKCS1SignerImpl pkcs1 = new PKCS1SignerImpl();

			// para token
			pkcs1.setPrivateKey((PrivateKey) ks.getKey(alias, null));

			// para arquivo
			// quando certificado em arquivo, precisa informar a senha
			// char[] senha = "senha".toCharArray();
			// signer.setPrivateKey((PrivateKey) ks.getKey(alias, senha));

					// para mudar o algoritimo
			pkcs1.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
			String varSO = System.getProperty("os.name");
			if (varSO.contains("indows")) {
				pkcs1.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);
			}

			/* Realiza a assinatura do conteudo */
			System.out.println("Efetuando a  assinatura do conteudo");
			// Assinatura desatachada

			byte[] signature = pkcs1.doDetachedSign(fileToSign);
			String varSignature = Base64.encodeBase64String(signature);
			System.out.println(varSignature);
			File file = new File(fileDirName + "_.p1s");
			FileOutputStream os = new FileOutputStream(file);
			os.write(signature);
			os.flush();
			os.close();
			System.out.println(pkcs1.getSignatory());
			//assertTrue(!pkcs1.getSignatory().isEmpty());

		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException ex) {
			ex.printStackTrace();
			assertTrue(false);
		}
	}


	/**
	 * Faz a leitura do token em LINUX, precisa setar a lib (.SO) e a senha do
	 * token.
	 */
	@SuppressWarnings("restriction")
	private KeyStore getKeyStoreToken() {

		try {
			// ATENÇÃO ALTERAR CONFIGURAÇÃO ABAIXO CONFORME O TOKEN USADO

			// Para TOKEN Branco a linha abaixo
			// String pkcs11LibraryPath = "/usr/lib/watchdata/ICP/lib/libwdpkcs_icp.so";

			// Para TOKEN Azul a linha abaixo
			String pkcs11LibraryPath = "/usr/lib/libeToken.so";

			StringBuilder buf = new StringBuilder();
			buf.append("library = ").append(pkcs11LibraryPath).append("\nname = Provedor\n");
			Provider p = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(buf.toString().getBytes()));
			Security.addProvider(p);
			// ATENÇÃO ALTERAR "SENHA" ABAIXO
			Builder builder = KeyStore.Builder.newInstance("PKCS11", p,
					new KeyStore.PasswordProtection("senha".toCharArray()));
			KeyStore ks;
			ks = builder.getKeyStore();

			return ks;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		}
	}

	// Usa o Signer para leitura, funciona para windows e NeoID
	private KeyStore getKeyStoreTokenBySigner() {

		try {

			KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
			KeyStore keyStore = keyStoreLoader.getKeyStore();

			return keyStore;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		}
	}

	// lê pelo InputStream
	@SuppressWarnings("unused")
	private KeyStore getKeyStoreStreamBySigner() {

		try {

			// informar o caminho e nome do arquivo
			String filep12 = "/";

			InputStream readStream = readStream(filep12);

			KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader(readStream);
			// Informar a senha
			KeyStore keystore = loader.getKeyStore("senha");
			return keystore;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		}
	}

	/**
	 * le a partir do arquivo .p12 ou pfx
	 *
	 * @return
	 */
	@SuppressWarnings("unused")
	private KeyStore getKeyStoreFileBySigner() {

		try {

			// informar o caminho e nome do arquivo
			File filep12 = new File("/");

			KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader(filep12);
			// Informar a senha
			KeyStore keystore = loader.getKeyStore("senha");
			return keystore;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		}
	}

	/**
	 * Keytore a partir de MSCAPI
	 */

	@SuppressWarnings("unused")
	private KeyStore getKeyStoreOnWindows() {
		try {
			MSKeyStoreLoader msKeyStoreLoader = new MSKeyStoreLoader();

			KeyStore ks = msKeyStoreLoader.getKeyStore();

			return ks;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		}
	}

	private byte[] readContent(String parmFile) {
		byte[] result = null;
		try {
			File file = new File(parmFile);
			FileInputStream is = new FileInputStream(parmFile);
			result = new byte[(int) file.length()];
			is.read(result);
			is.close();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return result;
	}

	private InputStream readStream(String parmFile) {
		InputStream result = null;
		try {
			// File file = new File(parmFile);
			result = new FileInputStream(parmFile);
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return result;
	}

	private String getAlias(KeyStore ks) {
		String alias = "";
		try {

			Enumeration<String> e;

			e = ks.aliases();
			while (e.hasMoreElements()) {
				alias = e.nextElement();
				System.out.println("alias..............: " + alias);
				System.out.println("iskeyEntry" + ks.isKeyEntry(alias));
				System.out.println("containsAlias" + ks.containsAlias(alias));
				// Certificate[] certificates = ks.getCertificateChain(alias);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return alias;
	}

}
