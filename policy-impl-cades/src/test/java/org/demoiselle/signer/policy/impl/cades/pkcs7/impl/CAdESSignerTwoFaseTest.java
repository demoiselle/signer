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

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.cms.CMSSignedData;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.core.keystore.loader.implementation.MSKeyStoreLoader;
import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.timestamp.configuration.TimeStampConfig;
import org.junit.Test;

import java.io.*;
import java.security.*;
import java.security.KeyStore.Builder;
import java.security.cert.Certificate;
import java.util.Enumeration;

import static org.junit.Assert.assertTrue;


/**
 *
 */
@SuppressWarnings("unused")
public class CAdESSignerTwoFaseTest {


	/**
	 * Teste para assinatura desanexada enviando conteúdo
	 */
	//@Test
	public void testSignDetached() {
		try {

			System.out.println("******** TESTANDO COM ARQUIVO *****************");

			// INFORMAR o arquivo

			//
			//String fileDirName = "C:\\Users\\{usuario}\\arquivo_assinar";
			String fileDirName = "/";
			
			
			byte[] fileToSign;

			//fileToSign = Base64.decodeBase64("VGVzdGUgQXNzaW5hdHVyYQo=");
			// se informar o fileDirName decomentar abaixo
			fileToSign = readContent(fileDirName);


			// MSCAPI off
			//org.demoiselle.signer.core.keystore.loader.configuration.Configuration.setMSCAPI_ON(false);

			// Setar Proxy
			// Proxy.setProxyEndereco("localhost");
			//Proxy.setProxyPorta("3128");
			//Proxy.setProxySenha("senha");
			//Proxy.setProxyUsuario("usuario");
			//Proxy.setProxy();


			// Para certificado NeoID e windows token
			KeyStore ks = getKeyStoreTokenBySigner();

			//// Para certificado em arquivo A1
			//KeyStore ks = getKeyStoreFileBySigner();
			// Para certificado token Linux
			//KeyStore ks = getKeyStoreToken();

			// Para certificados no so windows (mascapi)
			// KeyStore ks = getKeyStoreOnWindows();

			String alias = getAlias(ks);
			
			/* Parametrizando o objeto doSign */
			PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();

			signer.setCertificates(ks.getCertificateChain(alias));

			// para token
			signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));

			// para arquivo
			// quando certificado em arquivo, precisa informar a senha
			//char[] senha = "teste".toCharArray();
			//signer.setPrivateKey((PrivateKey) ks.getKey(alias, senha));

			// politica referencia básica sem carimbo de tempo
			//signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_3);
			// com carimbo de tempo
			//signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_3);
			// referencia de validação
			//signer.setSignaturePolicy(PolicyFactory.Policies.AD_RV_CADES_2_3);
			
			// para mudar o algoritimo
			signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
			String varSO = System.getProperty("os.name");
			if (varSO.contains("indows")) {
				signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);
			}

			/* Realiza a assinatura do conteudo */
			System.out.println("Preparando a  assinatura do tipo desanexada");
			// Assinatura desatachada

			// Cache de cadeia
			//CAManagerConfiguration config = CAManagerConfiguration.getInstance();
			//config.setCached(true);
			//org.demoiselle.signer.core.ca.manager.CAManagerConfiguration.getInstance().setCached(true);

			// Cache LCR
			//ConfigurationRepo config = ConfigurationRepo.getInstance();
			//config.setCrlIndex("crl_index");
			//config.setCrlPath("/tmp/lcr_cache/");
			//config.setOnline(false);
			//config.setValidateLCR(false);


			// Diretorio LPA
			//ConfigurationRepo config = ConfigurationRepo.getInstance();
			//config.setLpaPath("/home/signer/lpa/");
			// LPA online
			
			//config.setOnlineLPA(false);

			CMSSignedData csd = signer.prepareDetachedSign(fileToSign);
			
			System.out.println("Efetuando a  assinatura do tipo desanexada");

			// configurações de conexão para o timeStamp
			//TimeStampConfig tsConfig = TimeStampConfig.getInstance();
			//tsConfig.setTimeOut(100);
			//tsConfig.setConnectReplay(2);

			// Keystore diferente para timestamp
			//KeyStore ksToTS = getKeyStoreStreamBySigner();

			//String aliasToTs = getAlias(ksToTS);
			//char[] senhaTS = "senha".toCharArray();
			// pode ser outro certificado para timestamp
			//signer.setCertificatesForTimeStamp(ksToTS.getCertificateChain(aliasToTs));
			//signer.setPrivateKeyForTimeStamp((PrivateKey) ksToTS.getKey(aliasToTs, senhaTS));

			
			

			byte[] signature = signer.envelopDetachedSign(csd);
			
			File file = new File(fileDirName + "_detached_rt.p7s");
			FileOutputStream os = new FileOutputStream(file);
			os.write(signature);
			os.flush();
			os.close();
			System.out.println(signer.getSignatory());
			assertTrue(!signer.getSignatory().isEmpty());

		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException ex) {
			ex.printStackTrace();
			assertTrue(false);
		}
	}

	/**
	 * teste passando apenas o hash do arquivo 
	 */
	//@Test
	public void testSignWithHash() {
		try {

			System.out.println("******** TESTANDO COM HASH *****************");

			// INFORMAR o arquivo para gerar o hash
			String fileDirName = "/";
			


			byte[] fileToSign = readContent(fileDirName);


			// Para certificado em arquivo A1 é preciso essa senha para PrivateKey
			// para token troque a senha em: getKeyStoreToken()
			//char[] senha = "senha".toCharArray();

			// Para certificado em arquivo A1
			// KeyStore ks = getKeyStoreFile();

			// Para certificados no so windows (mascapi)
			// KeyStore ks = getKeyStoreOnWindows();


			// Para certificado em token
			//KeyStore ks = getKeyStoreToken();

			// Para certificado NeoID e windows token
			KeyStore ks = getKeyStoreTokenBySigner();


			String alias = getAlias(ks);
			/* Parametrizando o objeto doSign */
			PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
			signer.setCertificates(ks.getCertificateChain(alias));

			// gera o hash do arquivo
			java.security.MessageDigest md = java.security.MessageDigest
				.getInstance(DigestAlgorithmEnum.SHA_512.getAlgorithm());

			// devido a uma restrição do token branco, no windws só funciona com 256
			String varSO = System.getProperty("os.name");
			if (varSO.contains("indows")) {
				md = java.security.MessageDigest.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());
			}

			byte[] hash = md.digest(fileToSign);


			// seta o algoritmo de acordo com o que foi gerado o Hash
			signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
			if (varSO.contains("indows")) {
				signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);
			}

			// Para certificado em arquivo A1
			// signer.setPrivateKey((PrivateKey) ks.getKey(alias,senha));

			// Para certificado em token
			signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));

			// Sem carimbo de tempo
			//signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_3);

			// com carimbo de tempo
			 //signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_3);



			/* Realiza a assinatura do conteudo */
			System.out.println("preparando a  assinatura do hash");			
			
			CMSSignedData csd = signer.prepareHashSign(hash);
			
			System.out.println("Efetuando a  assinatura (hash)");

			//TimeStampConfig tsConfig = TimeStampConfig.getInstance();
			//tsConfig.setTimeOut(100);
			//tsConfig.setConnectReplay(2);

			// Keystore diferente para timestamp
			//KeyStore ksToTS = getKeyStoreStreamBySigner();

			//String aliasToTs = getAlias(ksToTS);
			//char[] senhaTS = "senha".toCharArray();
			
			// pode ser outro certificado para timestamp
			//signer.setCertificatesForTimeStamp(ksToTS.getCertificateChain(aliasToTs));
			//signer.setPrivateKeyForTimeStamp((PrivateKey) ksToTS.getKey(aliasToTs, senhaTS));

			byte[] signature = signer.envelopHashSign(csd);
			
			String signatureEncoded = new String(Base64.encodeBase64(signature));
			System.out.println("signatureEncoded :" + signatureEncoded);
			File file = new File(fileDirName + "by_hash.p7s");
			FileOutputStream os = new FileOutputStream(file);
			os.write(signature);
			os.flush();
			os.close();
			assertTrue(true);
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException ex) {
			ex.printStackTrace();
			assertTrue(false);
		}
	}

	/**
	 * Teste com conteúdo anexado
	 */
	//@Test
	public void testSignAttached() {
		try {

			System.out.println("******** TESTANDO COM CONTEÚDO ATACHADO*****************");

			// INFORMAR o arquivo
			String fileDirName = "/";


			byte[] fileToSign = readContent(fileDirName);

			// quando certificado em arquivo, precisa informar a senha
			//char[] senha = "senha".toCharArray();

			// Para certificado em Token
			//KeyStore ks = getKeyStoreToken();

			// Para certificado NeoID e windows token
			KeyStore ks = getKeyStoreTokenBySigner();


			// Para certificado em arquivo A1
			//KeyStore ks = getKeyStoreFile();

			// Para certificados no so windows (mascapi)
			// KeyStore ks = getKeyStoreOnWindows();

			String alias = getAlias(ks);
			/* Parametrizando o objeto doSign */
			PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
			signer.setCertificates(ks.getCertificateChain(alias));

			// para token
			signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));

			// para arquivo
			// signer.setPrivateKey((PrivateKey) ks.getKey(alias, senha));
			
			// politica sem carimbo de tempo
			//signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_3);
			
			// com carimbo de tempo
			//signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_3);

			// Referencia de validação
			//signer.setSignaturePolicy(PolicyFactory.Policies.AD_RA_CADES_2_4);

			// para mudar o algoritimo
			signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
			String varSO = System.getProperty("os.name");
			if (varSO.contains("indows")) {
				signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);
			}

			

			/* Realiza a assinatura do conteudo */
			System.out.println("preparando a  assinatura com conteudo anexado");
			// Com conteudo atachado
			
			CMSSignedData csd = signer.prepareAttachedSign(fileToSign);
			
			//TimeStampConfig tsConfig = TimeStampConfig.getInstance();
			//tsConfig.setTimeOut(100);
			//tsConfig.setConnectReplay(2);

			// Keystore diferente para timestamp
			//KeyStore ksToTS = getKeyStoreStreamBySigner();

			//String aliasToTs = getAlias(ksToTS);
			//char[] senhaTS = "senha".toCharArray();
			
			// pode ser outro certificado para timestamp
			//signer.setCertificatesForTimeStamp(ksToTS.getCertificateChain(aliasToTs));
			//signer.setPrivateKeyForTimeStamp((PrivateKey) ksToTS.getKey(aliasToTs, senhaTS));

			System.out.println("Envelopando a  assinatura com conteudo anexado");
			byte[] signature = signer.envelopHashSign(csd);
			
			File file = new File(fileDirName + "_attached.p7s");
			FileOutputStream os = new FileOutputStream(file);
			os.write(signature);
			os.flush();
			os.close();
			assertTrue(true);
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException ex) {
			ex.printStackTrace();
			assertTrue(false);
		}
	}

	

	
	
	// A anotação @Test está comentada, para passar o buld, pois as
	// configurações dependem de parâmetros
	// locais.

	/**
	 * Faz a leitura do token em LINUX, precisa setar a lib (.SO) e a senha do token.
	 */
	@SuppressWarnings("restriction")
	private KeyStore getKeyStoreToken() {

		try {
			// ATENÇÃO ALTERAR CONFIGURAÇÃO ABAIXO CONFORME O TOKEN USADO

			// Para TOKEN Branco a linha abaixo
			//String pkcs11LibraryPath =	 "/usr/lib/watchdata/ICP/lib/libwdpkcs_icp.so";

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
			String filep12 = "C:\\Users\\80621732915\\git\\neosigner\\assinador-api\\src\\main\\resources\\timestamp\\152156.p12";


			InputStream readStream = readStream(filep12);

			KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader(readStream);
			// Informar a senha
			KeyStore keystore = loader.getKeyStore("123456");
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
			KeyStore keystore = loader.getKeyStore("");
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
			result = new FileInputStream(parmFile);
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return result;
	}

	private String getAlias(KeyStore ks) {
		Certificate[] certificates = null;
		String alias = "";
		Enumeration<String> e;
		try {
			e = ks.aliases();
			while (e.hasMoreElements()) {
				alias = e.nextElement();
				System.out.println("alias..............: " + alias);
				System.out.println("iskeyEntry" + ks.isKeyEntry(alias));
				System.out.println("containsAlias" + ks.containsAlias(alias));
				certificates = ks.getCertificateChain(alias);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return alias;
	}
}
