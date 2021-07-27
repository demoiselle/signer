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


package org.demoiselle.signer.policy.impl.xades.xml;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.xades.XMLSignatureInformations;
import org.junit.Test;

public class XMLCheckerTest {

	@Test
	public void test() {
		
		try {
			String fileName = "teste_assinatura_rt_signed.xml";
			
	        ClassLoader classLoader = getClass().getClassLoader();
	        URL fileUri = classLoader.getResource(fileName);
	        File newFile=new File(fileUri.toURI());
	        
//	        InputStreamReader streamReader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
//	        BufferedReader reader = new BufferedReader(streamReader); 
	        			
			XMLChecker xadesChecker = new XMLChecker();
			if (xadesChecker.check(newFile.getPath())) {
				// Cache LCR
				ConfigurationRepo configlcr = ConfigurationRepo.getInstance();
				//configlcr.setCrlIndex(".crl_index");
				//configlcr.setCrlPath("/home/{usuario}/lcr_cache/");
				configlcr.setOnline(false);

				/* cache interno
				CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(buf),contents.getBytes());
		        SignerInformation signerInfo = (SignerInformation) cms.getSignerInfos().getSigners().iterator().next();
		        X509CertificateHolder certificateHolder = (X509CertificateHolder) cms.getCertificates().getMatches(signerInfo.getSID())
		                .iterator().next();
		        X509Certificate varCert = new JcaX509CertificateConverter().getCertificate(certificateHolder);
		        LcrManagerSync.getInstance().update(varCert);*/

				
				List<XMLSignatureInformations> results = new ArrayList<XMLSignatureInformations>();
				results = xadesChecker.getSignaturesInfo();
				if (!results.isEmpty()){
					for (XMLSignatureInformations sis : results){
						for (String valErr : sis.getValidatorErrors()){
							System.err.println( "++++++++++++++ ERROS ++++++++++++++++++");
							System.err.println(valErr);
						}
						
						for (String valWarn : sis.getValidatorWarnins()) {
							System.err.println("++++++++++++++ AVISOS ++++++++++++++++++");
							System.err.println(valWarn);
						}

						if (sis.getSignaturePolicy() != null){
							System.out.println("------ Politica ----------------- ");
							System.out.println(sis.getSignaturePolicy().toString());
							
						}
						
						BasicCertificate bc = sis.getIcpBrasilcertificate();
						System.out.println(bc.toString()); 
							if (bc.hasCertificatePF()){
								System.out.println(bc.getICPBRCertificatePF().getCPF());
							}
							if (bc.hasCertificatePJ()){
								System.out.println(bc.getICPBRCertificatePJ().getCNPJ());
								System.out.println(bc.getICPBRCertificatePJ().getResponsibleCPF());
							}
							
						if(sis.getTimeStampSigner()!= null) {
							System.out.println(sis.getTimeStampSigner().toString());
						}
					}			
					assertTrue(true);
				}
			}else {
				assertTrue(false);
			}
			
					
		} catch (Throwable e) {			
		  e.printStackTrace();
		  assertTrue(false);
		}		
	}

}
