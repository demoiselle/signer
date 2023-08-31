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

package org.demoiselle.signer.core.repository;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Representa um repositório online. Neste caso não ha necessidade de um serviço
 * para atualização das CRL. O Repositório deve primeiramente buscar a arquivo
 * no file system, caso o mesmo não se encontre ou ja esteja expirado ele obterá
 * a CRL a partir de sua URL.
 */
public class OnLineCRLRepository implements CRLRepository {

	private final Logger logger = LoggerFactory.getLogger(OnLineCRLRepository.class);
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();
	private Proxy proxy;

	public OnLineCRLRepository() {
		this.proxy = Proxy.NO_PROXY;
	}

	public OnLineCRLRepository(Proxy proxy) {
		this.proxy = proxy;
	}

	@Override
	public Collection<ICPBR_CRL> getX509CRL(X509Certificate certificate) throws NoSuchProviderException {

		Collection<ICPBR_CRL> list = new ArrayList<ICPBR_CRL>();
		try {
			BasicCertificate cert = new BasicCertificate(certificate);
			List<String> ListaURLCRL = cert.getCRLDistributionPoint();

			if (ListaURLCRL == null || ListaURLCRL.isEmpty()) {
				logger.error(coreMessagesBundle.getString("error.invalid.crl"));
				throw new CRLRepositoryException(coreMessagesBundle.getString("error.invalid.crl"));
			}

			ICPBR_CRL validCrl = null;
			for (String URLCRL : ListaURLCRL) {
				// Achou uma CRL válida
				validCrl = getICPBR_CRL(URLCRL);
				if (validCrl != null) {
					list.add(validCrl);
					logger.debug(coreMessagesBundle.getString("info.crl.found", URLCRL));
					break;
				}
			}
			if (validCrl == null) {
				logger.error(coreMessagesBundle.getString("error.validate.on.crl", ListaURLCRL));
				throw new CRLRepositoryException(coreMessagesBundle.getString("error.validate.on.crl", ListaURLCRL));
			}
		} catch (IOException e) {
			logger.error(coreMessagesBundle.getString("error.invalid.crl") + e.getMessage());
			throw new CRLRepositoryException(coreMessagesBundle.getString("error.invalid.crl") + e.getMessage());
		}
		return list;
	}

	protected ICPBR_CRL getICPBR_CRL(String uRLCRL) throws NoSuchProviderException {
		ICPBR_CRL icpbr_crl = null;
		try {
			URL url = new URL(uRLCRL);
			InputStream is;
			URLConnection uCon = url.openConnection(proxy);
			ConfigurationRepo conf = ConfigurationRepo.getInstance();
			uCon.setConnectTimeout(conf.getCrlTimeOut());
			uCon.setReadTimeout(conf.getCrlTimeOut());			
			try {				
				is = uCon.getInputStream();
			} catch (IOException e) {
				logger.debug(e.getMessage());
				String newUrl = uRLCRL.replace("http://", "https://");
				uRLCRL = newUrl;
				logger.info(newUrl);
				url = new URL(newUrl);
				uCon = url.openConnection(conf.getProxy());
				uCon.setConnectTimeout(conf.getCrlTimeOut());
				uCon.setReadTimeout(conf.getCrlTimeOut());
				is = uCon.getInputStream();
			}			
			
			DataInputStream inStream = new DataInputStream(is);
			icpbr_crl = new ICPBR_CRL(inStream);
			inStream.close();
		} catch (MalformedURLException e) {
			logger.error(coreMessagesBundle.getString("error.malformedURL", uRLCRL).concat(e.getMessage()));
			icpbr_crl = null;
		} catch (IOException e) {
			logger.error(coreMessagesBundle.getString("error.crl.connect", uRLCRL).concat(e.getMessage()));
			icpbr_crl = null;
		} catch (CRLException e) {
			logger.error(coreMessagesBundle.getString("error.crl.exception", uRLCRL).concat(e.getMessage()));
			icpbr_crl = null;
		} catch (CertificateException e) {
			logger.error(coreMessagesBundle.getString("error.crl.certificate", uRLCRL).concat(e.getMessage()));
			icpbr_crl = null;
		}
		
		return icpbr_crl;
	}
}
