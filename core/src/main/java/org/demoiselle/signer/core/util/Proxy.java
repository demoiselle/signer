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

package org.demoiselle.signer.core.util;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configure proxy for networking.
 */
public final class Proxy {

	private static String proxyEndereco = null;
	private static String proxyPorta = null;
	private static String proxyUsuario = "";
	private static String proxySenha = "";
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();
	private static final Logger LOGGER = LoggerFactory.getLogger(Proxy.class.getName());

	public Proxy() {
	}

	public static void setProxy() throws Exception {
		try {
			if (proxyEndereco == null
				|| proxyEndereco.trim().isEmpty()
				|| proxyPorta == null
				|| proxyPorta.trim().isEmpty()) {
				LOGGER.error(coreMessagesBundle.getString("error.proxy.empty.values", proxyEndereco, proxyPorta));
				throw new Exception(coreMessagesBundle.getString("error.proxy.empty.values", proxyEndereco, proxyPorta));
			}

			Authenticator.setDefault(
				new Authenticator() {
					@Override
					public PasswordAuthentication getPasswordAuthentication() {
						return new PasswordAuthentication(
							proxyUsuario, proxySenha.toCharArray());
					}
				}
			);
			System.setProperty("http.proxyHost", proxyEndereco);
			System.setProperty("http.proxyPort", proxyPorta);
			System.setProperty("http.proxyUser", proxyUsuario);
			System.setProperty("http.proxyPassword", proxySenha);
			System.setProperty("https.proxyHost", proxyEndereco);
			System.setProperty("https.proxyPort", proxyPorta);
			System.setProperty("https.proxyUser", proxyUsuario);
			System.setProperty("https.proxyPassword", proxySenha);
			LOGGER.info(coreMessagesBundle.getString("info.proxy.running", proxyEndereco, proxyPorta, proxyUsuario));

		} catch (Exception e) {
			LOGGER.error(coreMessagesBundle.getString("error.proxy", proxyEndereco, proxyPorta, proxyUsuario, e.getMessage()));
			throw new Exception(coreMessagesBundle.getString("error.proxy", proxyEndereco, proxyPorta, proxyUsuario, e.getMessage()));
		}
	}

	public static String getProxyEndereco() {
		return proxyEndereco;
	}

	public static void setProxyEndereco(String proxyEndereco) {
		Proxy.proxyEndereco = proxyEndereco;
	}

	public static String getProxyPorta() {
		return proxyPorta;
	}

	public static void setProxyPorta(String proxyPorta) {
		Proxy.proxyPorta = proxyPorta;
	}

	public static String getProxyUsuario() {
		return proxyUsuario;
	}

	public static void setProxyUsuario(String proxyUsuario) {
		Proxy.proxyUsuario = proxyUsuario;
	}

	public static String getProxySenha() {
		return proxySenha;
	}

	public static void setProxySenha(String proxySenha) {
		Proxy.proxySenha = proxySenha;
	}
}
