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
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

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

	
	//@Test
	public void testVerifyDetachedSignature() {
		String fileToVerifyDirName = "/home/arquivo.txt";
		String fileSignatureDirName = "/home/arquivo.txt.p7s";
			
				
		byte[] fileToVerify = readContent(fileToVerifyDirName);
		byte[] signatureFile = readContent(fileSignatureDirName);
		
		CAdESChecker checker = new CAdESChecker();

		System.out.println("Efetuando a validacao da assinatura");
		List<SignatureInformations> signaturesInfo = checker.checkDetattachedSignature(fileToVerify, signatureFile);
		
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

	
	//@Test
	public void testVerifyAttachedSignature() {
		String fileSignatureDirName = "/home/arquivo.txt.p7s";
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
	
	
	// @Test
	public void testVerifySignatureByHash() {
		String fileSignatureDirName = "local_e_nome_do_arquivo_da_assinatura";
		String fileToVerifyDirName = "local_e_nome_do_arquivo_assinado";
		
		
							
		byte[] fileToVerify = readContent(fileToVerifyDirName);
				
		byte[] signatureFile = readContent(fileSignatureDirName);

		java.security.MessageDigest md;
		try {
			md = java.security.MessageDigest
					.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());
		
			// gera o hash do arquivo que foi assinado
			byte[] hash = md.digest(fileToVerify);
		
			CAdESChecker checker = new CAdESChecker();
		
			System.out.println("Efetuando a validacao da assinatura");
					
			List<SignatureInformations> signaturesInfo = checker.checkSignatureByHash(SignerAlgorithmEnum.SHA256withRSA.getOIDAlgorithmHash(), hash, signatureFile);
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
	
}