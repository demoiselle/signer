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

package org.demoiselle.signer.chain.icp.brasil.provider.hom;

import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.demoiselle.signer.core.ca.provider.ProviderCA;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * WARNING: USE ONLY ON HOMOLOGATION ENVIROMENT
 * <p>
 * Provides homologation (with purpose of tests) FAKE Certificate Authority chain of the ICP-BRAZIL's
 */
public class HomologacaoProviderCA implements ProviderCA {

	protected static MessagesBundle chainMessagesBundle = new MessagesBundle();
	private static final Logger logger = LoggerFactory.getLogger(HomologacaoProviderCA.class);

	@SuppressWarnings("finally")
	public Collection<X509Certificate> getCAs() {
		List<X509Certificate> result = new ArrayList<X509Certificate>();
		try {

			InputStream AutoridadeCertificadoraRaizBrasileirav10HML = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraRaizBrasileirav10-HML.crt");
			InputStream AutoridadeCertificadoradoSERPROSSLv3Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROSSLv3-Hom.crt");
			InputStream AutoridadeCertificadoraRaizBrasileirav10 = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraRaizBrasileirav10.crt");
			InputStream AutoridadeCertificadoradoSERPROSSLv1Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROSSLv1Hom.crt");
			InputStream AutoridadeCertificadoradoSERPROFinalv5HomN = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROFinalv5-Hom.crt");
			InputStream AutoridadeCertificadoraSERPROv6HOM = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSERPROv6HOM.crt");
			InputStream AutoridadeCertificadoraRaizHomdoSERPRO = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraRaizHomdoSERPRO.crt");
			InputStream serproACFv4Homolog = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/serproACFv4Homolog.cer");
			InputStream IntermediariaHOMv2 = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/IntermediariaHOMv2.cer");
			InputStream AutoridadeCertificadoraSERPRORFBSSLHom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSERPRORFBSSLHom.crt");
			InputStream AutoridadeCertificadoraSERPRODesenv = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSERPRODesenv.crt");
			InputStream AutoridadeCertificadoraSERPROACFv4Homologacao = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSERPROACFv4Homologacao.crt");
			InputStream AutoridadeCertificadoraRaizdeHomologacaoSERPROv2 = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraRaizdeHomologacaoSERPROv2.crt");
			InputStream AutoridadeCertificadoraRaizdeHomologacaoSERPRO = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraRaizdeHomologacaoSERPRO.crt");
			InputStream AutoridadeCertificadoraIntermediariaHOMv2 = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraIntermediariaHOMv2.crt");
			InputStream AutoridadeCertificadoradoSERPRORFBSSLHom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPRORFBSSLHom.crt");
			InputStream AutoridadeCertificadoradoSERPRORFBHomologacao = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPRORFBHomologacao.crt");
			InputStream AutoridadeCertificadoradoSERPROFinalv5HOM = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROFinalv5HOM.crt");
			InputStream AutoridadeCertificadoradoSERPROFinalTimeStampingHom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROFinalTimeStampingHom.crt");
			InputStream AutoridadeCertificadoradoSERPROFinalSSLv2HOM = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROFinalSSLv2HOM.crt");
			InputStream AutoridadeCertificadoradoSERPROFinalSSLHom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROFinalSSLHom.crt");
			InputStream AutoridadeCertificadoradoSERPROFinalCodeSigningHom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROFinalCodeSigningHom.crt");
			InputStream AutoridadeCertificadoradaPresidenciadaRepublicav4HOM = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradaPresidenciadaRepublicav4HOM.crt");
			InputStream AutoridadeCertificadoradaCasadaMoedadoBrasilv6HOM = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradaCasadaMoedadoBrasilv6HOM.crt");
			InputStream AutoridadeCertificadoradaCasadaMoedadoBrasilv5Teste = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradaCasadaMoedadoBrasilv5Teste.crt");
			InputStream AutoridadeCertificadoradaCasadaMoedadoBrasilv4Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradaCasadaMoedadoBrasilv4Hom.crt");
			InputStream AutoridadeCertificadoraACSERPRORFBv3Homologacao = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraACSERPRORFBv3Homologacao.crt");
			InputStream AutoridadeCertificadoraACSERPROACFv3Homologacao = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraACSERPROACFv3Homologacao.crt");
			InputStream ACSERPROJUSv5 = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/ACSERPROJUSv5.crt");
			InputStream ACSERPROHOMOLOGACAO = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/ACSERPROHOMOLOGACAO.crt");
			InputStream ACSERPROACFv3Homologacao = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/ACSERPROACFv3Homologacao.cer");
			InputStream AutoridadeCertificadoraSERPRORFBv5Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSERPRORFBv5Hom.crt");
			InputStream AutoridadeCertificadoradoSERPROFinalSSL_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROFinalSSL_Hom.crt");
			InputStream AutoridadeCertificadoradoSERPROV2 = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROV2.crt");
			InputStream AutoridadeCertificadoradoSERPROFinalv6Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROFinalv6Hom.crt");
			InputStream AutoridadeCertificadoraSERPROv2HOM = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSERPROv2HOM.crt");
			InputStream AutoridadeCertificadoraRaizHomdoSERPROv2 = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraRaizHomdoSERPROv2.crt");
						
			InputStream AutoridadeCertificadoradoSERPRORFBSSLv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPRORFBSSLv2-Hom.crt");
			InputStream AutoridadeCertificadoraSERPRORFBv6_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSERPRORFBv6-Hom.crt");
			InputStream AutoridadeCertificadoraSERPRORFBv5_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSERPRORFBv5-Hom.crt");
			InputStream AutoridadeCertificadoradoSERPROFinalSSLv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSERPROFinalSSLv2-Hom.crt");
			InputStream AutoridadeCertificadoraSEFAZCEv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSEFAZCEv2-Hom.crt");
			InputStream AutoridadeCertificadoraSDIv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSDIv2-Hom.crt");
			InputStream AutoridadeCertificadoraSAFE_IDBRASILv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSAFE-IDBRASILv2-Hom.crt");
			InputStream AutoridadeCertificadoraPROCERTIv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraPROCERTIv2-Hom.crt");
			InputStream AutoridadeCertificadoraPRIMECERTv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraPRIMECERTv2-Hom.crt");
			InputStream AutoridadeCertificadoraINVIAv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraINVIAv2-Hom.crt");
			InputStream AutoridadeCertificadoraINFOCOMEX_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraINFOCOMEX-Hom.crt");
			InputStream AutoridadeCertificadoraSERPROv2_HOM = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraSERPROv2-HOM.crt");
			InputStream AutoridadeCertificadoraCERTFYv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraCERTFYv2-Hom.crt");
			InputStream AutoridadeCertificadoraBRASILCERTECv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraBRASILCERTECv2-Hom.crt");
			InputStream AutoridadeCertificadoraALTERNATIVEv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraALTERNATIVEv2-Hom.crt");
			InputStream AutoridadeCertificadoradoSEBRAERFBv2_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradoSEBRAERFBv2-Hom.crt");
			InputStream AutoridadeCertificadoradaPresidenciadaRepublicav6_Hom = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradaPresidenciadaRepublicav6-Hom.crt");
			InputStream AutoridadeCertificadoraRaizBrasileirav4 = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraRaizBrasileirav4.crt");
			InputStream AutoridadeCertificadoraMinisteriodasRelacoesExteriores_HO = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraMinisteriodasRelacoesExteriores-HO.crt");
			InputStream AutoridadeCertificadoraRaizdoSERPRO = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraRaizdoSERPRO.crt");
			InputStream AutoridadeCertificadoradeAutenticacaodaCAIXAHOM = HomologacaoProviderCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoradeAutenticacaodaCAIXAHOM.crt");
			
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraRaizBrasileirav10HML));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROSSLv3Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraRaizBrasileirav10));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROSSLv1Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROFinalv5HomN));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSERPROv6HOM));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraRaizHomdoSERPRO));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(serproACFv4Homolog));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(IntermediariaHOMv2));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSERPRORFBSSLHom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSERPRODesenv));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSERPROACFv4Homologacao));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraRaizdeHomologacaoSERPROv2));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraRaizdeHomologacaoSERPRO));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraIntermediariaHOMv2));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPRORFBSSLHom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPRORFBHomologacao));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROFinalv5HOM));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROFinalTimeStampingHom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROFinalSSLv2HOM));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROFinalSSLHom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROFinalCodeSigningHom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradaPresidenciadaRepublicav4HOM));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradaCasadaMoedadoBrasilv6HOM));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradaCasadaMoedadoBrasilv5Teste));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradaCasadaMoedadoBrasilv4Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraACSERPRORFBv3Homologacao));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraACSERPROACFv3Homologacao));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(ACSERPROJUSv5));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(ACSERPROHOMOLOGACAO));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(ACSERPROACFv3Homologacao));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSERPRORFBv5Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROFinalSSL_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROV2));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROFinalv6Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSERPROv2HOM));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraRaizHomdoSERPROv2));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPRORFBSSLv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSERPRORFBv6_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSERPRORFBv5_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSERPROFinalSSLv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSEFAZCEv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSDIv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSAFE_IDBRASILv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraPROCERTIv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraPRIMECERTv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraINVIAv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraINFOCOMEX_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraSERPROv2_HOM));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraCERTFYv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraBRASILCERTECv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraALTERNATIVEv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradoSEBRAERFBv2_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradaPresidenciadaRepublicav6_Hom));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraRaizBrasileirav4));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraMinisteriodasRelacoesExteriores_HO));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraRaizdoSERPRO));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoradeAutenticacaodaCAIXAHOM));


		} catch (Throwable error) {
			logger.error(error.getMessage());
			return null;
		} finally {
			return result;
		}
	}

	public String getName() {
		return chainMessagesBundle.getString("info.provider.name.hom.serpro");
	}
}
