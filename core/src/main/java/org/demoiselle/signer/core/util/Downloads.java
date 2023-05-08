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

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownServiceException;

import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Offer download service.
 */
public class Downloads {

	private static MessagesBundle coreMessagesBundle = new MessagesBundle();
	private static Logger logger = LoggerFactory.getLogger(Downloads.class);

	/**
	 * Get the input stream from provided address.
	 *
	 * @param stringURL sequence from with an {@link InputStream} will be returned.
	 *
	 * @return the {@link InputStream} corresponding to the other param.
	 */
	public static InputStream getInputStreamFromURL(final String stringURL) throws RuntimeException {
		try {
			InputStream is = null;
			URL url = new URL(stringURL);
			URLConnection connection;
			ConfigurationRepo conf = ConfigurationRepo.getInstance();
			connection = url.openConnection(conf.getProxy());
			connection.setConnectTimeout(conf.getCrlTimeOut());
			connection.setReadTimeout(conf.getCrlTimeOut());
			
			try {
				is = connection.getInputStream();
			} catch (IOException e) {
				String newUrl = stringURL.replace("http://", "https://");
				logger.info(newUrl);
				url = new URL(newUrl);
				connection = url.openConnection(conf.getProxy());
				connection.setConnectTimeout(conf.getCrlTimeOut());
				connection.setReadTimeout(conf.getCrlTimeOut());
				is = connection.getInputStream();
			}			
			
			return is; 
		} catch (MalformedURLException error) {
			throw new RuntimeException(coreMessagesBundle.getString("error.malformedURL", error.getMessage()), error);
		} catch (UnknownServiceException error) {
			throw new RuntimeException(coreMessagesBundle.getString("error.unknown.service", error.getMessage()),
					error);
		} catch (IOException error) {
			throw new RuntimeException(coreMessagesBundle.getString("error.io", error.getMessage()), error);
		}
	}
}
