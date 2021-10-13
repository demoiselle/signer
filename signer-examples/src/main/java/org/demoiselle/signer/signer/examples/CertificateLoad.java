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

package org.demoiselle.signer.signer.examples;

import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.demoiselle.signer.core.CertificateManager;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateLoad {

	private static final Logger logger = LoggerFactory.getLogger(CertificateLoad.class);

	public static KeyStoreLoader keyStoreLoader;
	public static KeyStore keyStore;
	public static X509Certificate certificate;
	public static PrivateKey privateKey;
	public static char[] password = "caro84867944".toCharArray();
	public static Certificate[] certificateChain;

	public static void main(String[] args) {

		try {
			// Carrega a keystore (TOKEN)
			keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();

			keyStoreLoader.setCallbackHandler(new CallbackHandler() {
				public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
					for (Callback callback : callbacks) {
						if (callback instanceof PasswordCallback) {
							((PasswordCallback) callback).setPassword(password);
						}
					}
				}
			});

			keyStore = keyStoreLoader.getKeyStore();

			Enumeration<String> aliases = keyStore.aliases();

			while (aliases.hasMoreElements()) {

				String alias = aliases.nextElement();

				System.out.println("Alias: " + alias);

				certificate = (X509Certificate) keyStore.getCertificate(alias);
				privateKey = (PrivateKey) keyStore.getKey(alias, null);
				certificateChain = keyStore.getCertificateChain(alias);

				try {

					CertificateManager cm = new CertificateManager(certificate);
					CertICPBrasil cert = cm.load(CertICPBrasil.class);
					logger.info("CPF: {0}", cert.getCpf());

					// BasicCertificate bc = new BasicCertificate(certificate);
					// logger.info("Nome....................[{0}]",
					// bc.getNome());
					// logger.info("E-mail..................[{0}]",
					// bc.getEmail());
					// logger.info("Numero de serie.........[{0}]",
					// bc.getSerialNumber());
				} catch (Exception e) {
					logger.error("Erro ao carregar o certificado (ICP Brasil) com alias [" + alias + "]", e);
				}

			}

		} catch (Throwable e) {

			e.printStackTrace();

		}

	}
}
