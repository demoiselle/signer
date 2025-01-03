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

package org.demoiselle.signer.timestamp.connector;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.timestamp.configuration.TimeStampConfig;
import org.demoiselle.signer.timestamp.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The following simple TCP-based protocol is to be used for transport of TSA messages.
 * This protocol is suitable for cases where an entity
 * initiates a transaction and can poll to pick up the results.
 * <p>
 * The protocol basically assumes a listener process on a TSA that can
 * accept TSA messages on a well-defined port (IP port number 318).
 * <p>
 * Typically an initiator binds to this port and submits the initial TSA message.
 * The responder replies with a TSA message and/or with a reference number
 * to be used later when polling for the actual TSA  message response.
 * <p>
 * If a number of TSA response messages are to be produced for a given
 * request (say if a receipt must be sent before the actual token can be
 * produced) then a new polling reference is also returned.
 * <p>
 * When the final TSA response message has been picked up by the
 * initiator then no new polling reference is supplied.
 *
 * @author 07721825741
 */
public class SocketConnector implements Connector {

	private static final Logger logger = LoggerFactory.getLogger(SocketConnector.class);
	private static MessagesBundle timeStampMessagesBundle = new MessagesBundle();

	private String hostname = "";
	private int port;
	private OutputStream out = null;
	private Socket socket = null;

	@Override
	public InputStream connect(byte[] content) throws CertificateCoreException {
		try {
			TimeStampConfig.getInstance().getTimeOut();
			logger.debug(timeStampMessagesBundle.getString("info.timestamp.send.request"));
			socket = new Socket(hostname, port);
			logger.debug(timeStampMessagesBundle.getString("info.timestamp.timeout.value", TimeStampConfig.getInstance().getTimeOut()));
			socket.setSoTimeout(TimeStampConfig.getInstance().getTimeOut());
			logger.debug(timeStampMessagesBundle.getString("info.timestamp.connected", new Object[]{socket.isConnected(), hostname, port}));

			logger.debug(timeStampMessagesBundle.getString("info.timestamp.socket.write"));
			// A "direct TCP-based TSA message" consists of:length (32-bits), flag (8-bits), value
			out = socket.getOutputStream();
			out.write(Utils.intToByteArray(1 + content.length));
			out.write(0x00);
			out.write(content);
			out.flush();

			logger.debug(timeStampMessagesBundle.getString("info.timestamp.socket.response"));
			return socket.getInputStream();
		} catch (IOException e) {
			logger.error(e.getMessage());
			throw new CertificateCoreException(timeStampMessagesBundle.getString("error.timestamp.socket", e.getMessage()));
		}
	}

	@Override
	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	@Override
	public void setPort(int port) {
		this.port = port;
	}

	@Override
	public void close() {
		try {
			socket.close();
			out.close();
		} catch (IOException ex) {
			logger.debug(ex.getMessage());
		}

	}
}
