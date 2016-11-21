/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
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
package org.demoiselle.signer.signature.signer.pkcs7.attribute.impl;

import org.demoiselle.signer.signature.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.signature.signer.pkcs7.attribute.SignedAttribute;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ContentType implements SignedAttribute {

    private static final Logger logger = LoggerFactory.getLogger(ContentType.class);
    private final String identifier = "1.2.840.113549.1.9.3";

    @Override
    public String getOID() {
        return identifier;
    }

    @Override
    public Attribute getValue() {
        return new Attribute(new ASN1ObjectIdentifier(identifier), new DERSet(new ASN1ObjectIdentifier(contentType.data.getOid())));
    }

    @Override
    public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy) {

    }

    private enum contentType {

        data("1.2.840.113549.1.7.1"),
        signedData("1.2.840.113549.1.7.2"),
        envelopedData("1.2.840.113549.1.7.3"),
        signedAndEnvelopedData("1.2.840.113549.1.7.4"),
        digestedData("1.2.840.113549.1.7.5"),
        encryptedData("1.2.840.113549.1.7.6");

        private String oid;

        private contentType(String oid) {
            this.oid = oid;
        }

        public String getOid() {
            return oid;
        }
    }
}
