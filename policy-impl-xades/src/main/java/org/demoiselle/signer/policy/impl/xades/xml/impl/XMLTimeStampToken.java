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

package org.demoiselle.signer.policy.impl.xades.xml.impl;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import org.demoiselle.signer.core.timestamp.TimeStampGenerator;
import org.demoiselle.signer.core.timestamp.TimeStampGeneratorSelector;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.policy.impl.xades.XMLSignerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * Request a TimeStampToken from Certificate Autority  (TSA).
 *
 * @author Emerson Sachio Saito &lt;emerson.saito@serpro.gov.br&gt;
 *
 */
public class XMLTimeStampToken {

	private static final Logger logger = LoggerFactory.getLogger(XMLTimeStampToken.class);
	private static final TimeStampGenerator timeStampGenerator = TimeStampGeneratorSelector.selectReference();
    private static MessagesBundle xadesMessagesBundle = new MessagesBundle();
    private PrivateKey privateKey = null;
    private Certificate[] certificates = null;
    private byte[] content = null;
    private byte[] hash = null;


	public XMLTimeStampToken(PrivateKey privateKey, Certificate[] certificates, byte[] content, byte[] hash) {
		super();
		this.privateKey = privateKey;
		this.certificates = certificates;
		this.content = content;
		this.hash = hash;
	}

	public byte[] getTimeStampToken() throws XMLSignerException {
		byte[] response = null;
        try {
            logger.debug(xadesMessagesBundle.getString("info.tsa.connecting"));

            if (timeStampGenerator != null) {
                  //Inicializa os valores para requisição do Carimbo do Tempo
            	timeStampGenerator.initialize(content, privateKey, certificates, hash);

                //Obtem o carimbo de tempo atraves do servidor ACT
                response = timeStampGenerator.generateTimeStamp();

                //Valida o carimbo de tempo gerado
                timeStampGenerator.validateTimeStamp(content, response, hash);
            } else {
                throw new XMLSignerException(xadesMessagesBundle.getString("error.tsa.not.found"));
            }
        } catch (SecurityException  ex) {
            throw new XMLSignerException(ex.getMessage());
        }
		return response;

	}



}
