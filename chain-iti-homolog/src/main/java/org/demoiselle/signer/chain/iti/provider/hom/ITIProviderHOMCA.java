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

package org.demoiselle.signer.chain.iti.provider.hom;

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
 * Provides HOM Certificate Authority chain of ITI
 * https://assinador.iti.br/assinatura/
 * http://repo.iti.br/docs/Cadeia_GovBr-der-hom.p7b
 * 
 */
public class ITIProviderHOMCA implements ProviderCA {

	protected static MessagesBundle chainMessagesBundle = new MessagesBundle();
	private static final Logger logger = LoggerFactory.getLogger(ITIProviderHOMCA.class);

	@SuppressWarnings("finally")
	public Collection<X509Certificate> getCAs() {
		List<X509Certificate> result = new ArrayList<X509Certificate>();
		try {

			// CADEIAS de HOMOLOGAÇÃO
			
			
			InputStream AutoridadeCertificadoraRaizdoGovernoFederaldoBrasilHOM =
				ITIProviderHOMCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadoraRaizdoGovernoFederaldoBrasilHOM.crt");
			InputStream AutoridadeCertificadora1NiveldoGovernoFederaldoBrasilHOM =
				ITIProviderHOMCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadora1NiveldoGovernoFederaldoBrasilHOM.crt");
			InputStream AutoridadeCertificadora2NiveldoGovernoFederaldoBrasilHOM =
					ITIProviderHOMCA.class.getClassLoader().getResourceAsStream("trustedca/AutoridadeCertificadora2NiveldoGovernoFederaldoBrasilHOM.crt");
			
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			logger.debug(chainMessagesBundle.getString("info.provider.name.serpro.neosigner"));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadoraRaizdoGovernoFederaldoBrasilHOM));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadora1NiveldoGovernoFederaldoBrasilHOM));
			result.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(AutoridadeCertificadora2NiveldoGovernoFederaldoBrasilHOM));
			
		} catch (Throwable error) {
			logger.error(error.getMessage());
			return null;
		} finally {
			return result;
		}
	}

	public String getName() {
		return chainMessagesBundle.getString("info.provider.name.iti.gov.hom");
	}
}
