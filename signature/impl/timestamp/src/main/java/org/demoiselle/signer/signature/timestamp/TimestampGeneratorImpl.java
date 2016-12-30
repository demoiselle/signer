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
package org.demoiselle.signer.signature.timestamp;

import org.demoiselle.signer.signature.core.Priority;
import org.demoiselle.signer.signature.core.exception.CertificateCoreException;
import org.demoiselle.signer.signature.core.timestamp.TimeStampGenerator;
import org.demoiselle.signer.signature.timestamp.connector.TimeStampOperator;
import java.security.PrivateKey;
import java.security.cert.Certificate;


@Priority(Priority.MIN_PRIORITY)
public class TimestampGeneratorImpl implements TimeStampGenerator {

    //private static final Logger logger = LoggerFactory.getLogger(TimestampGeneratorImpl.class);

    private byte[] content;
    private PrivateKey privateKey;
    private Certificate[] certificates;
    
    /**
     * Inicializa os atributos necessarios para obter o carimbo de tempo
     *
     * @param content
     * @param privateKey
     * @param certificates
     * @throws CertificateCoreException
     */
    @Override
    public void initialize(byte[] content, PrivateKey privateKey, Certificate[] certificates) throws CertificateCoreException {
        this.content = content;
        this.privateKey = privateKey;
        this.certificates = certificates;        
    }

    /**
     * Envia a requisicao de carimbo de tempo para um servidor de carimbo de
     * tempo
     *
     * @return O carimbo de tempo retornado pelo servidor
     */
    @Override
    public byte[] generateTimeStamp() throws CertificateCoreException {
        TimeStampOperator timeStampOperator = new TimeStampOperator();
        byte[] request = timeStampOperator.createRequest(privateKey, certificates, content);
        return timeStampOperator.invoke(request);
    }

    /**
     * Valida um carimnbo de tempo e o documento original
     *
     * @param content o conteudo original
     * @param response O carimbo de tempo a ser validado
     *
     */
    @Override
    public void validateTimeStamp(byte[] content, byte[] response) throws CertificateCoreException {

        //Valida a assinatura digital do carimbo de tempo
        TimeStampOperator timeStampOperator = new TimeStampOperator();
        timeStampOperator.validate(content, response);
    }
}
