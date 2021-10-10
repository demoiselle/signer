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

import java.io.File;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * Defines the basic methods for loading a certificate depending
 * on the storage format.
 */
public interface CertificateLoader {

	/**
	 * Obtains the certificate from a file, defined by ICP-BRASIL
	 * with the name A1.
	 *
	 * @param file The file that contains the certificate.
	 * @return the certificate information in X509Certificate format.
	 * @throws CertificateCoreException in case of problem in loading.
	 */
	X509Certificate load(File file) throws CertificateCoreException;

	/**
	 * Obtain the certificate from a Token or Smartcard, defined by
	 * ICP-BRASIL with the name A3.
	 *
	 * @return the certificate information in X509Certificate format.
	 * @throws CertificateCoreException in case of problem in loading.
	 */
	X509Certificate loadFromToken() throws CertificateCoreException;

	/**
	 * When a PIN  (Personal Identification Number) was informed,
	 * obtain the certificate from a Token or Smartcard, defined by
	 * ICP-BRASIL with the name A3.
	 *
	 * @param pinNumber personal identification number.
	 * @return the certificate information in X509Certificate format.
	 * @throws CertificateCoreException in case of problem in loading.
	 */
	X509Certificate loadFromToken(String pinNumber) throws CertificateCoreException;

	/**
	 * When a PIN (Personal Identification Number) and Alias was informed,
	 * obtain the certificate from a Token or Smartcard, defined by
	 * ICP-BRASIL with the name A3.
	 *
	 * @param pinNumber a PIN (Personal Identification Number).
	 * @param alias     desired alias.
	 * @return the certificate information in X509Certificate format.
	 * @throws CertificateCoreException in case of problem in loading.
	 */
	X509Certificate loadFromToken(String pinNumber, String alias) throws CertificateCoreException;

	/**
	 * Associate a previously existing keystore.
	 *
	 * @param keyStore an existing {@link KeyStore}.
	 * @throws CertificateCoreException if is not possible to set the
	 * keystore.
	 */
	void setKeyStore(KeyStore keyStore) throws CertificateCoreException;

	/**
	 * Returns the KeyStore used by {@link CertificateLoader}.
	 *
	 * @return A keystore used ({@link KeyStore}).
	 * @throws CertificateCoreException if is not possible to
	 * get keystore.
	 */
	KeyStore getKeyStore() throws CertificateCoreException;
}
