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

package org.demoiselle.signer.timestamp.connector;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.net.ssl.HttpsURLConnection;

import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Time-Stamp Protocol via HTTP
 * <p>
 * This subsection specifies a means for conveying ASN.1-encoded
 * messages for the protocol exchanges described in Section 2 and
 * Appendix D via the HyperText Transfer Protocol.
 * <p>
 * Two MIME objects are specified as follows.
 * <p>
 * Content-Type: application/timestamp-query
 * <p>
 * &lt;&lt;the ASN.1 DER-encoded Time-Stamp Request message&gt;&gt;
 * <p>
 * Content-Type: application/timestamp-reply
 * <p>
 * &lt;&lt;the ASN.1 DER-encoded Time-Stamp Response message&gt;&gt;
 * <p>
 * These MIME objects can be sent and received using common HTTP
 * processing engines over WWW links and provides a simple browser-
 * server transport for Time-Stamp messages.
 * <p>
 * Upon receiving a valid request, the server MUST respond with either a
 * valid response with content type application/timestamp-response or with an HTTP error.
 *
 * @author 07721825741
 */
public class HttpConnector implements Connector {

	private static final Logger logger = LoggerFactory.getLogger(HttpConnector.class);
	private String hostname;
	private int port;
	private OutputStream out = null;
	private HttpsURLConnection HttpsConnector;

	private static MessagesBundle timeStampMessagesBundle = new MessagesBundle();

	@Override
	public InputStream connect(byte[] content) {
		logger.info(timeStampMessagesBundle.getString("error.not.supported", getClass().getName()));
		throw new UnsupportedOperationException(timeStampMessagesBundle.getString("error.not.supported", getClass().getName()));
	}

	@Override
	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	@Override
	public void setPort(int port) {
		this.port = port;
	}

	public HttpsURLConnection getHttpsConnector() {
		return HttpsConnector;
	}

	public void setHttpsConnector(HttpsURLConnection httpsConnector) {
		HttpsConnector = httpsConnector;
	}

	public String getHostname() {
		return hostname;
	}

	public int getPort() {
		return port;
	}

	@Override
	public void close() {
		try {
			this.HttpsConnector.disconnect();
			this.out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
