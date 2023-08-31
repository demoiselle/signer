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

package org.demoiselle.signer.core;

import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Implements the basic methods for loading a certificate depending on the storage format
 */
public class CertificateLoaderImpl implements CertificateLoader {

	private KeyStore keyStore;

	/**
	 * Returns the KeyStore used by {@link CertificateLoader}.
	 *
	 * @return java.security.keystore
	 */

	@Override
	public KeyStore getKeyStore() {
		return keyStore;
	}

	/**
	 * Associate a previously existing keystore
	 *
	 * @param keyStore java.security.keystore
	 */

	@Override
	public void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}

	/**
	 * Obtains the certificate from a file, defined by ICP-BRASIL with the name A1.
	 *
	 * @param file The file that contains the certificate
	 * @return the certificate information in X509Certificate format
	 */

	@Override
	public X509Certificate load(File file) {
		try {
			FileInputStream fileInput = new FileInputStream(file);
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
			return (X509Certificate) cf.generateCertificate(fileInput);
		} catch (FileNotFoundException e) {
			throw new CertificateCoreException("FileNotFoundException", e);
		} catch (CertificateException e) {
			throw new CertificateCoreException("CertificateException", e);
		} catch (NoSuchProviderException e) {
			throw new CertificateCoreException("NoSuchProviderException", e);
		}
	}

	/**
	 * Obtain the certificate from a Token or Smartcard,
	 * defined by ICP-BRASIL with the name A3.
	 *
	 * @return the certificate information in X509Certificate format.
	 */
	@Override
	public X509Certificate loadFromToken() {
		return loadFromToken(null);
	}

	/**
	 * When a PIN(Personal Identification Number) was informed,
	 * obtain the certificate from a Token or Smartcard, defined
	 * by ICP-BRASIL with the name A3.
	 *
	 * @param pinNumber personal id number.
	 * @return the certificate information in X509Certificate format.
	 */
	@Override
	public X509Certificate loadFromToken(String pinNumber) {
		if (this.keyStore == null) {
			KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
			this.keyStore = keyStoreLoader.getKeyStore();
		}
		String alias;
		try {
			alias = this.keyStore.aliases().nextElement();
			return (X509Certificate) this.keyStore.getCertificateChain(alias)[0];
		} catch (KeyStoreException e) {
			throw new CertificateCoreException("", e);
		}

	}

	/**
	 * When a PIN (Personal Identification Number) and alias was informed,
	 * obtain the certificate from a Token or Smartcard,
	 * defined by ICP-BRASIL with the name A3.
	 *
	 * @param pinNumber a PIN (Personal Identification Number).
	 * @param alias     desired alias.
	 * @return the certificate information in X509Certificate format.
	 */
	@Override
	public X509Certificate loadFromToken(String pinNumber, String alias) {
		if (this.keyStore == null) {
			KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
			this.keyStore = keyStoreLoader.getKeyStore();
		}
		try {
			return (X509Certificate) this.keyStore.getCertificateChain(alias)[0];
		} catch (KeyStoreException e) {
			throw new CertificateCoreException("", e);
		}
	}
}
