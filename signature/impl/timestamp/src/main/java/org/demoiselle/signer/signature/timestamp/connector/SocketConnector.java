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
package org.demoiselle.signer.signature.timestamp.connector;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.demoiselle.signer.signature.timestamp.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class SocketConnector implements Connector {

    private static final Logger logger = LoggerFactory.getLogger(SocketConnector.class);

    private String hostname = "";
    private int port;
    private OutputStream out = null;
    private Socket socket = null;

    @Override
    public InputStream connect(byte[] content) {
        try {
            logger.info("Envia a solicitacao para o servidor TSA");
            socket = new Socket(hostname, port);

            logger.info("Conectado [{}] na url [{}] e porta [{}]", new Object[]{socket.isConnected(), hostname, port});

            logger.info("Escrevendo no socket");
            // A "direct TCP-based TSA message" consists of:length (32-bits), flag (8-bits), value
            out = socket.getOutputStream();
            out.write(Utils.intToByteArray(1 + content.length));
            out.write(0x00);
            out.write(content);
            out.flush();

            logger.info("Obtendo o response");
            return socket.getInputStream();
        } catch (IOException e) {
        	e.printStackTrace();
            logger.info(e.getMessage());
        }
        return null;
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
            logger.info(ex.getMessage());
        }

    }
}
