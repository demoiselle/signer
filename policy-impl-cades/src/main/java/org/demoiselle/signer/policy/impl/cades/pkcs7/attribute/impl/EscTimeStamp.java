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
package org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.impl;

import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.UnsignedAttribute;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.bouncycastle.asn1.cms.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * This attribute is used for the Type 1 X-Time-Stamped validation data.
 * The ES-C Time-Stamp attribute is an unsigned attribute. 
 *  It is time-stamp of a hash of the electronic signature and the complete validation data (ES-C). 
 *  It is a special purpose TimeStampToken  Attribute which time-stamps the ES-C. 
 *  Several instances instance of this attribute may occur with an 
 *  electronic signature from different TSAs.
 *  
 *  The following object identifier identifies the ES-C Time-Stamp attribute:
 *  
 *  id-aa-ets-escTimeStamp OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
 *   rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 25}
 *   
 *   The ES-C time-stamp attribute value has the ASN.1 syntax ESCTimeStampToken.
 *   
 *   ESCTimeStampToken ::= TimeStampToken
 *   
 *   The value of messageImprint field within TimeStampToken must be a
 *   hash of the concatenated values (without the type or length encoding
 *   for that value) of the following data objects as present in the 
 *   ES with Complete validation data (ES-C):
 *   
 *   signature field within SignerInfo;
 *   SignatureTimeStampToken attribute;
 *   CompleteCertificateRefs attribute;
 *   CompleteRevocationRefs attribute.
 *   
 *   
 */
public class EscTimeStamp implements UnsignedAttribute {

    private static final Logger logger = LoggerFactory.getLogger(RevocationRefs.class);
    private final String identifier = "1.2.840.113549.1.9.16.2.25";
    private static MessagesBundle cadesMessagesBundle = new MessagesBundle();

    @Override
    public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy) {
        logger.info(cadesMessagesBundle.getString("error.not.supported",getClass().getName()));
    }

    @Override
    public String getOID() {
        return identifier;
    }

    @Override
    public Attribute getValue() throws SignerException {
        throw new UnsupportedOperationException(cadesMessagesBundle.getString("error.not.supported",getClass().getName()));
    }

}
