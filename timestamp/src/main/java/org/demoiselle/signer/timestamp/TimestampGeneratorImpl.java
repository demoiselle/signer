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
package org.demoiselle.signer.timestamp;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.demoiselle.signer.core.Priority;
import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.core.timestamp.TimeStampGenerator;
import org.demoiselle.signer.timestamp.connector.TimeStampOperator;

/**
 * Methods for generate a TimeStamp based on  Timestamping Authority (TSA) service
 * RFC 3161
  *
 */

@Priority(Priority.MIN_PRIORITY)
public class TimestampGeneratorImpl implements TimeStampGenerator {


    private byte[] content = null;
    private PrivateKey privateKey;
    private Certificate[] certificates;
    private byte[] hash = null;
    
    /**
     * Initializes the attributes needed to get the time stamp
     *
     * @param content if it is assigned, the parameter hash must to be null
     * @param privateKey
     * @param certificates
     * @param hash if it is assigned, the parameter content must to be null
     * @throws CertificateCoreException
     */
    @Override
    public void initialize(byte[] content, PrivateKey privateKey, Certificate[] certificates, byte[] hash) throws CertificateCoreException {
        this.content = content;
        this.privateKey = privateKey;
        this.certificates = certificates;
        this.hash = hash;
    }

    /**
     * Sends the time stamp request to a time stamp server
     *
     * @return The time stamp returned by the server
     */
    @Override
    public byte[] generateTimeStamp() throws CertificateCoreException {
        TimeStampOperator timeStampOperator = new TimeStampOperator();
        byte[] request = timeStampOperator.createRequest(privateKey, certificates, content, hash);
        return timeStampOperator.invoke(request);
    }

    /**
     * Validate a time stamp and the original content
     *
     * @param content 
     * @param timestamp
     *
     */
    @Override
    public void validateTimeStamp(byte[] content, byte[] timestamp, byte[] hash) throws CertificateCoreException {

        //Valida a assinatura digital do carimbo de tempo
        TimeStampOperator timeStampOperator = new TimeStampOperator();
        timeStampOperator.validate(content, timestamp, hash);
    }
}
