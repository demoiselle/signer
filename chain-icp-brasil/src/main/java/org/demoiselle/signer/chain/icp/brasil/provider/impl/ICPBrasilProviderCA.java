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

package org.demoiselle.signer.chain.icp.brasil.provider.impl;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.demoiselle.signer.core.ca.provider.ProviderCA;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FIXME rename to ICPBrasilKeystoreProviderCA for consistence
 * Provides trusted Certificate Authority chain of the ICP-BRAZIL's digital signature policies
 * from Keystore (icpbrasil.jks) stored in resources library
 */
public class ICPBrasilProviderCA implements ProviderCA {

	private static MessagesBundle chainMessagesBundle = new MessagesBundle();
	Logger LOGGER = LoggerFactory.getLogger(ICPBrasilProviderCA.class);

	/**
	 * read Certificate Authority chain from loaded keystore
	 */
	@Override
	public Collection<X509Certificate> getCAs() {
		KeyStore keyStore = this.getKeyStore();
		List<X509Certificate> result = new ArrayList<X509Certificate>();
		try {
			for (Enumeration<String> e = keyStore.aliases(); e.hasMoreElements(); ) {
				String alias = e.nextElement();
				X509Certificate root = (X509Certificate) keyStore.getCertificate(alias);
				result.add(root);

			}
		} catch (KeyStoreException ex) {
			LOGGER.error(chainMessagesBundle.getString("error.load.keystore", ex.getMessage()), ex);
			throw new ICPBrasilProviderCAException(chainMessagesBundle.getString("error.load.keystore", ex.getMessage()), ex);
		}
		return result;
	}

	/**
	 * Load from file icpbrasil.jks
	 */
	private KeyStore getKeyStore() {
		KeyStore keyStore = null;
		LOGGER.debug(chainMessagesBundle.getString("info.ca.component"));
		try {
			InputStream is = ICPBrasilProviderCA.class.getClassLoader().getResourceAsStream("cadeiasicpbrasil.bks");
			//keyStore = KeyStore.getInstance("JKS", "SUN");
			Security.addProvider(new BouncyCastleProvider());
			keyStore = KeyStore.getInstance("BKS", "BC");
			//keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(is, "serprosigner".toCharArray());
		} catch (KeyStoreException ex) {
			LOGGER.error(chainMessagesBundle.getString("error.load.keystore", ex.getMessage()), ex);
			throw new ICPBrasilProviderCAException(chainMessagesBundle.getString("error.load.keystore", ex.getMessage()), ex);
		} catch (NoSuchAlgorithmException ex) {
			LOGGER.error(chainMessagesBundle.getString("error.no.algorithm", ex.getMessage()), ex);
			throw new ICPBrasilProviderCAException(chainMessagesBundle.getString("error.no.algorithm", ex.getMessage()), ex);
		} catch (CertificateException ex) {
			LOGGER.error(chainMessagesBundle.getString("error.jks.certificate", ex.getMessage()), ex);
			throw new ICPBrasilProviderCAException(chainMessagesBundle.getString("error.jks.certificate", ex.getMessage()), ex);
		} catch (IOException ex) {
			LOGGER.error(chainMessagesBundle.getString("error.io", ex.getMessage()), ex);
			throw new ICPBrasilProviderCAException(chainMessagesBundle.getString("error.io", ex.getMessage()), ex);
		} catch (NoSuchProviderException ex) {
			LOGGER.error(chainMessagesBundle.getString("error.io", ex.getMessage()), ex);
			throw new ICPBrasilProviderCAException(chainMessagesBundle.getString("error.io", ex.getMessage()), ex);

		}
		return keyStore;
	}

	/**
	 * This provider Name.
	 *
	 * @return the provider name.
	 */
	@Override
	public String getName() {
		return chainMessagesBundle.getString("info.provider.name.demoiselle");
	}
}
