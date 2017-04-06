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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.junit.Test;

/**
 *
 */
public class CAdESSignerTest {

	// TODO teste depende de configuração de ambiente do usuário, devemos criar
	// uma alternativa, ESTÁ COMENTADO PARA PASSAR NO BUILD
	
	
	/**
	 *  
	 * Faz a leitura do token, precisa setar a lib (.SO)  e a senha do token.
	 */
	private  KeyStore getKeyStore(){
		
		try {
			// 	ATENÇÃO ALTERAR CONFIGURAÇÃO ABAIXO CONFORME O TOKEN USADO
			// 	Para TOKEN Branco a linha abaixo
			// String pkcs11LibraryPath =
			// "/usr/lib/watchdata/ICP/lib/libwdpkcs_icp.so";
			// Para TOKEN Azul a linha abaixo
			String pkcs11LibraryPath = "/usr/lib/libeToken.so";
			StringBuilder buf = new StringBuilder();
			buf.append("library = ").append(pkcs11LibraryPath).append("\nname = Provedor\n");
			Provider p = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(buf.toString().getBytes()));
			Security.addProvider(p);

			// 	ATENÇÃO ALTERAR "SENHA" ABAIXO
			Builder builder = KeyStore.Builder.newInstance("PKCS11", p,
					new KeyStore.PasswordProtection("Senha".toCharArray()));
			KeyStore ks;
			ks = builder.getKeyStore();
			return ks;

		} catch (KeyStoreException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return null;
		}
				
	}


	/**
	 * Teste com envio do conteúdo
	 */
	//@Test
	public void testSignWithContent() {
		try {

			System.out.println("******** TESTANDO COM CONTEÚDO *****************");
			
			// INFORMAR o arquivo
			String fileDirName = "/home/{usuario}/arquivo_assinar.txt";

			byte[] fileToSign = readContent(fileDirName);

			KeyStore ks = getKeyStore();
			String alias = getAlias(ks);
			/* Parametrizando o objeto doSign */
			PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
			signer.setCertificates(ks.getCertificateChain(alias));
			signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));
			// politica sem carimbo de tempo
			signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_2);
			// com carimbo de tempo
			//signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_2);
			
			// para mudar o algoritimo
			//signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
			

			/* Realiza a assinatura do conteudo */
			System.out.println("Efetuando a  assinatura do conteudo");
			// Com conteudo atachado
			//byte[] signature = signer.doAttachedSign(fileToSign);
			
			// Assinatura desatachada
			 byte[] signature = signer.doDetachedSign(fileToSign);

			boolean checked = false;
			/* Valida o conteudo antes de gravar em arquivo */
			System.out.println("Efetuando a validacao da assinatura.");
			checked = signer.check(fileToSign, signature);

			if (checked) {
				System.out.println("A assinatura foi validada.");
			} else {
				System.out.println("A assinatura foi invalidada!");
			}

			try {
				File file = new File(fileDirName + ".p7s");
				FileOutputStream os = new FileOutputStream(file);
				os.write(signature);
				os.flush();
				os.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}

			/* Valida o conteudo depois de gravado */
			System.out.println("Efetuando a validacao da assinatura do arquivo gravado.");
			byte[] singnatureFile = readContent(fileDirName + ".p7s");
			checked = signer.check(fileToSign, singnatureFile);
			if (checked) {
				System.out.println("A assinatura foi validada.");
			} else {
				System.out.println("A assinatura foi invalidada!");
			}

		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
			ex.printStackTrace();
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
			String fileDirName = "/home/{usuario}/arquivo_assinar.txt";

			byte[] fileToSign = readContent(fileDirName);

			// gera o hash do arquivo
			java.security.MessageDigest md = java.security.MessageDigest.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());
			byte[] hash = md.digest(fileToSign);

			
			KeyStore ks = getKeyStore();
			String alias = getAlias(ks);
			/* Parametrizando o objeto doSign */
			PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
			signer.setCertificates(ks.getCertificateChain(alias));
			signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));
			// Sem carimbo de tempo
			signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_2);
			
			// com carimbo de tempo
			// signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_2);
			
			// muda algoritmo
			//signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);

			/* Realiza a assinatura do conteudo */
			System.out.println("Efetuando a  assinatura do hash");
			byte[] signature = signer.doHashSign(hash);


			boolean checked = false;
			/* Valida o conteudo antes de gravar em arquivo */
			System.out.println("Efetuando a validacao da assinatura.");
			checked = signer.check(fileToSign, signature);

			if (checked) {
				System.out.println("A assinatura foi validada.");
			} else {
				System.out.println("A assinatura foi invalidada!");
			}

			try {
				File file = new File(fileDirName + ".p7s");
				FileOutputStream os = new FileOutputStream(file);
				os.write(signature);
				os.flush();
				os.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}

		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
			ex.printStackTrace();
		}
	}
	

	// @Test
	public void testVerifySignature() {
		String fileToVerifyDirName = "local_e_nome_do_arquivo_assinado";
		byte[] fileToVerify = readContent(fileToVerifyDirName);
		String fileSignatureDirName = "local_e_nome_do_arquivo_da_assinatura";
		byte[] signatureFile = readContent(fileSignatureDirName);

		PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();

		System.out.println("Efetuando a validacao da assinatura");
		boolean checked = signer.check(fileToVerify, signatureFile);
		if (checked) {
			System.out.println("A assinatura foi validada.");
		} else {
			System.out.println("A assinatura foi invalidada!");
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
			
	private String getAlias (KeyStore ks){
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