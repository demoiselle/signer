/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
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

package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.timestamp.Timestamp;
import org.junit.Ignore;

import javax.net.ssl.KeyManagerFactory;
import java.io.*;
import java.security.*;
import java.security.KeyStore.Builder;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import static org.junit.Assert.assertTrue;

@Ignore
@SuppressWarnings("unused")
public class CAdESTimeStampSignerTest {

	// TESTES COMENTADOS PARA BUILD

	//@Test
	public void testDoTimeStampForSignature() {
		String fileSignatureDirName = "/.p7s";

		try {

			// Para certificado em Token
			//KeyStore ks = getKeyStoreToken();

			// Para certificados no so windows ou NeoID
			KeyStore ks = getKeyStoreTokenBySigner();

			// Para certificado em arquivo A1
			// KeyStore ks = getKeyStoreFile();

			// quando certificado em arquivo, precisa informar a senha
			//char[] senha = "senha".toCharArray();

			String alias = getAlias(ks);

			byte[] signatureFile = readContent(fileSignatureDirName);
			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();

			varCAdESTimeStampSigner.setCertificates(ks.getCertificateChain(alias));

			// para token
			varCAdESTimeStampSigner.setPrivateKey((PrivateKey) ks.getKey(alias, null));

			// para arquivo
			// signer.setPrivateKey((PrivateKey) ks.getKey(alias, senha));

			byte[] signatureWithTimeStamp = varCAdESTimeStampSigner
				.doTimeStampForSignature(signatureFile);

			File file = new File(fileSignatureDirName + "_timestamp" + ".p7s");
			FileOutputStream os = new FileOutputStream(file);
			os.write(signatureWithTimeStamp);
			os.flush();
			os.close();
			assertTrue(true);

		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);
		}

	}

	//@Test
	public void testDoTimeStampForContent() {
		String fileDirName = "/";

		try {

			// Para certificado em Token
			KeyStore ks = getKeyStoreToken();

			// Para certificados no so windows (mascapi)
			// KeyStore ks = getKeyStoreOnWindows();


			// Para certificado em arquivo A1
			// KeyStore ks = getKeyStoreFile();

			// quando certificado em arquivo, precisa informar a senha
			//char[] senha = "senha".toCharArray();


			String alias = getAlias(ks);

			byte[] content = readContent(fileDirName);
			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();

			varCAdESTimeStampSigner.setCertificates(ks.getCertificateChain(alias));

			// para token
			varCAdESTimeStampSigner.setPrivateKey((PrivateKey) ks.getKey(alias, null));

			// para arquivo
			// signer.setPrivateKey((PrivateKey) ks.getKey(alias, senha));

			byte[] timeStampForContent = varCAdESTimeStampSigner.doTimeStampForContent(content);

			File file = new File(fileDirName + "junit.timestamp.p7s");
			FileOutputStream os = new FileOutputStream(file);
			os.write(timeStampForContent);
			os.flush();
			os.close();
			assertTrue(true);

		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);
		}

	}

	//@Test
	public void testDoTimeStampForHashContent() {
		String fileDirName = "local_e_nome_do_arquivo";

		try {

			// Para certificado em Token
			KeyStore ks = getKeyStoreToken();

			// Para certificados no so windows (mascapi)
			// KeyStore ks = getKeyStoreOnWindows();

			// Para certificado em arquivo A1
			// KeyStore ks = getKeyStoreFile();

			// quando certificado em arquivo, precisa informar a senha
			//char[] senha = "senha".toCharArray();


			String alias = getAlias(ks);

			byte[] content = readContent(fileDirName);


			String varSO = System.getProperty("os.name");
			java.security.MessageDigest md = null;
			if (varSO.contains("indows")) {
				// gera o hash do conteudo
				 md = java.security.MessageDigest
					.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());			
			}else {
				 md = java.security.MessageDigest
						.getInstance(DigestAlgorithmEnum.SHA_512.getAlgorithm());				
			}		
				
			byte[] hash = md.digest(content);

			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();

			varCAdESTimeStampSigner.setCertificates(ks.getCertificateChain(alias));

			// para token
			varCAdESTimeStampSigner.setPrivateKey((PrivateKey) ks.getKey(alias, null));

			// para arquivo
			// signer.setPrivateKey((PrivateKey) ks.getKey(alias, senha));

			byte[] timeStampForContent = varCAdESTimeStampSigner.doTimeStampFromHashContent(hash);

			File file = new File(fileDirName + "_fromHash" + ".timestamp.p7s");
			FileOutputStream os = new FileOutputStream(file);
			os.write(timeStampForContent);
			os.flush();
			os.close();
			assertTrue(true);

		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);
		}
	}

	//@Test
	public void testCheckTimeStampOnSignature() {
		String fileSignatureDirName = "/";


		try {
			byte[] signatureFile = readContent(fileSignatureDirName);
			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();
			List<Timestamp> listTimeStamp = varCAdESTimeStampSigner.checkTimeStampOnSignature(signatureFile);
			if (!listTimeStamp.isEmpty()) {
				for (Timestamp ts : listTimeStamp) {
					System.out.println(ts.toString());
					assertTrue(true);
				}
			} else {
				assertTrue(false);
			}

		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);
		}

	}

	//@Test
	public void testCheckTimeStampWithContent() {
		String fileTimeStampDirName = "/.p7s";
		String fileContentDirName = "/";


		try {
			byte[] timeStampFile = readContent(fileTimeStampDirName);
			byte[] content = readContent(fileContentDirName);
			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();
			Timestamp varTimeStamp = varCAdESTimeStampSigner.checkTimeStampWithContent(timeStampFile, content);
			if (varTimeStamp != null) {
				System.out.println(varTimeStamp.toString());
				assertTrue(true);
			} else {
				assertTrue(false);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);
		}
	}

	//@Test
	public void testCheckTimeStampWithHash() {
		String fileTimeStampDirName = "local_e_nome_do_arquivo_da_assinatura";
		String fileContentDirName = "local_e_nome_do_arquivo_assinado";
		try {
			byte[] timeStampFile = readContent(fileTimeStampDirName);
			byte[] content = readContent(fileContentDirName);
			// gera o hash do conteudo
			
			java.security.MessageDigest md = null;
			String varSO = System.getProperty("os.name");
			if (varSO.contains("indows")) {
				// gera o hash do conteudo
				 md = java.security.MessageDigest
					.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());			
			}else {
				 md = java.security.MessageDigest
						.getInstance(DigestAlgorithmEnum.SHA_512.getAlgorithm());				
			}			
			
			byte[] hash = md.digest(content);
			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();
			Timestamp varTimeStamp = varCAdESTimeStampSigner.checkTimeStampWithHash(timeStampFile, hash);
			if (varTimeStamp != null) {
				System.out.println(varTimeStamp.toString());
				assertTrue(true);
			} else {
				assertTrue(false);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);
		}
	}

	/**
	 * FIXME goes to core
	 * @param parmFile file to read
	 * @return content of file.
	 */
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

	@SuppressWarnings("restriction")
	private KeyStore getKeyStoreToken() {

		try {
			// ATENÇÃO ALTERAR CONFIGURAÇÃO ABAIXO CONFORME O TOKEN USADO

			// Para TOKEN Branco a linha abaixo
			// String pkcs11LibraryPath =
			// "/usr/lib/watchdata/ICP/lib/libwdpkcs_icp.so";

			// Para TOKEN Azul a linha abaixo
			String pkcs11LibraryPath = "/usr/lib/libeToken.so";

			StringBuilder buf = new StringBuilder();
			buf.append("library = ").append(pkcs11LibraryPath).append("\nname = Provedor\n");
			Provider p = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(buf.toString().getBytes()));
			Security.addProvider(p);
			// ATENÇÃO ALTERAR "SENHA" ABAIXO
			Builder builder = KeyStore.Builder.newInstance("PKCS11", p, new KeyStore.PasswordProtection("senha".toCharArray()));
			KeyStore ks;
			ks = builder.getKeyStore();

			return ks;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		}
	}

	/**
	 * Faz a leitura do certificado armazenado em arquivo (A1).
	 *
	 * @return keystore obtido de arquivo.
	 */
	private KeyStore getKeyStoreFile() {

		try {
			KeyStore ks = KeyStore.getInstance("pkcs12");

			// Alterar a senha
			char[] senha = "senha".toCharArray();

			// informar onde esta o arquivo
			InputStream ksIs = new FileInputStream("/home/{usuario}/xx.p12");
			ks.load(ksIs, senha);

			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(ks, senha);

			return ks;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		}

	}


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

	private String getAlias(KeyStore ks) {
		Certificate[] certificates = null;
		String alias = "";
		Enumeration<String> e;
		try {
			e = ks.aliases();
			while (e.hasMoreElements()) {
				alias = e.nextElement();
				System.out.println("alias..............: {}" + alias);
				certificates = ks.getCertificateChain(alias);
			}

		} catch (KeyStoreException e1) {
			e1.printStackTrace();
		}
		X509Certificate c = (X509Certificate) certificates[0];
		System.out.println("Número de série....: {}" + c.getSerialNumber().toString());
		return alias;
	}

}
