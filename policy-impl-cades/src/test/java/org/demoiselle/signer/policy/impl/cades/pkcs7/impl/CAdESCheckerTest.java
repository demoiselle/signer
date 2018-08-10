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

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.junit.Test;

/**
 *
 */
@SuppressWarnings("unused")
public class CAdESCheckerTest {

	
	/**
	 * Verifica assinatura desanexada do arquivo
	 */
	//@Test
	public void testVerifyDetachedSignature() {
		String fileToVerifyDirName = "/home/{usuario}/arquivo";
		String fileSignatureDirName = "/home/{usuario}/arquivo.p7s";
		
		
		
		
				
		byte[] fileToVerify = readContent(fileToVerifyDirName);
		byte[] signatureFile = readContent(fileSignatureDirName);
		
		CAdESChecker checker = new CAdESChecker();

		System.out.println("Efetuando a validacao da assinatura");
		List<SignatureInformations> signaturesInfo = checker.checkDetachedSignature(fileToVerify, signatureFile);
		
		if (signaturesInfo != null) {
			System.out.println("A assinatura foi validada.");
			for (SignatureInformations si : signaturesInfo){
				System.out.println(si.getSignDate());
				if (si.getTimeStampSigner() != null){
					System.out.println("Serial"+si.getTimeStampSigner().toString());
				}
				for(X509Certificate cert : si.getChain()){
					BasicCertificate certificate = new BasicCertificate(cert);
					if (!certificate.isCACertificate()){
						System.out.println(certificate.toString());
					}												
				}
				for (String valErr : si.getValidatorErrors()){
					System.out.println( "++++++++++++++ ERROS ++++++++++++++++++");
					System.out.println(valErr);
				}
				if (si.getSignaturePolicy() != null){
					System.out.println("------ Politica ----------------- ");
					System.out.println(si.getSignaturePolicy().toString());
				}
				
			}
			assertTrue(true);	
		
		} else {
			System.out.println("A assinatura foi invalidada!");
			assertTrue(false);
		}
	}

	
	/**
	 * Verifica assinatura com conteúdo anexado
	 */
	//@Test
	public void testVerifyAttachedSignature() {
		
		
		String fileSignatureDirName = "local_e_nome_do_arquivo_da_assinatura_com_conteudo_anexado";
		byte[] signatureFile = readContent(fileSignatureDirName);

		CAdESChecker checker = new CAdESChecker();

		System.out.println("Efetuando a validacao da assinatura");
		List<SignatureInformations> signaturesInfo =  checker.checkAttachedSignature(signatureFile);
		if (signaturesInfo != null) {
			System.out.println("A assinatura foi validada.");
			for (SignatureInformations si : signaturesInfo){
				System.out.println(si.getSignDate());
				if (si.getTimeStampSigner() != null){
					System.out.println("Serial"+si.getTimeStampSigner().toString());
				}
				for(X509Certificate cert : si.getChain()){
					BasicCertificate certificate = new BasicCertificate(cert);
					if (!certificate.isCACertificate()){
						System.out.println(certificate.toString());
					}												
				}
				for (String valErr : si.getValidatorErrors()){
					System.out.println( "++++++++++++++ ERROS ++++++++++++++++++");
					System.out.println(valErr);
				}
				System.out.println(si.getSignaturePolicy().toString());
			}
			assertTrue(true);		
		
		} else {
			System.out.println("A assinatura foi invalidada!");
			assertTrue(false);
		}
	}
	
	
	/**
	 * Verifica assinatura desanexada do arquivo, com envio apenas do Hash do arquivo anexado.
	 * Neste exemplo, informa-se o arquivo que foi assinado para facilitar o teste.
	 */
	//@Test
	public void testVerifySignatureByHash() {
		String fileSignatureDirName = "local_e_nome_do_arquivo_da_assinatura";
		
		// Apenas para gerar o HASH
		String fileToVerifyDirName = "local_e_nome_do_arquivo_assinado";
		
							
		byte[] fileToVerify = readContent(fileToVerifyDirName);
				
		byte[] signatureFile = readContent(fileSignatureDirName);

		java.security.MessageDigest md;
		try {
			md = java.security.MessageDigest
					.getInstance(DigestAlgorithmEnum.SHA_512.getAlgorithm());
		
			// gera o hash do arquivo que foi assinado
			byte[] hash = md.digest(fileToVerify);
		
			CAdESChecker checker = new CAdESChecker();
		
			System.out.println("Efetuando a validacao da assinatura");
					
			List<SignatureInformations> signaturesInfo = checker.checkSignatureByHash(SignerAlgorithmEnum.SHA512withRSA.getOIDAlgorithmHash(), hash, signatureFile);
			if (signaturesInfo != null) {
				System.out.println("A assinatura foi validada.");
				for (SignatureInformations si : signaturesInfo){
					System.out.println(si.getSignDate());
					if (si.getTimeStampSigner() != null){
						System.out.println("Serial"+si.getTimeStampSigner().toString());
					}
					for(X509Certificate cert : si.getChain()){
						BasicCertificate certificate = new BasicCertificate(cert);
						if (!certificate.isCACertificate()){
							System.out.println(certificate.toString());
						}												
					}
					for (String valErr : si.getValidatorErrors()){
						System.out.println( "++++++++++++++ ERROS ++++++++++++++++++");
						System.out.println(valErr);
					}
					System.out.println(si.getSignaturePolicy().toString());
				}
				assertTrue(true);
			} else {
				System.out.println("A assinatura foi invalidada!");
				assertTrue(false);
			}
		} catch (Exception e) {
			e.printStackTrace();
			assertTrue(false);
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
	
	//@Test
	public void testGerarDoHash() {
		String imgPDF = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
		
		
		byte[] signature = Base64.decodeBase64(imgPDF);
		File file = new File("conteudo.txt");
		FileOutputStream os;
		try {
			os = new FileOutputStream(file);
			os.write(signature);
			os.flush();
			os.close();

		} catch (IOException e) {		
			e.printStackTrace();
		}
		
		}
	
	
}