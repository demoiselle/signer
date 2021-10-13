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

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.demoiselle.signer.core.timestamp.TimeStampGenerator;
import org.demoiselle.signer.core.timestamp.TimeStampGeneratorSelector;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.UnsignedAttribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *  *
 *  It is defined as a ContentInfo([CMS]) and SHALL encapsulate a signed data content type.
 *
 *   	TimeStampToken ::= ContentInfo
 *        -- contentType is id-signedData ([CMS])
 *        -- content is SignedData ([CMS])
 *
 *
 *       id-aa-timeStampToken OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *          us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) aa(2) 14 }
 *
 */
public class TimeStampToken implements UnsignedAttribute {

    private static final Logger logger = LoggerFactory.getLogger(TimeStampToken.class);
    private static final TimeStampGenerator timeStampGenerator = TimeStampGeneratorSelector.selectReference();
    private static MessagesBundle cadesMessagesBundle = new MessagesBundle();

    private final ASN1ObjectIdentifier identifier = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
    private PrivateKey privateKey = null;
    private Certificate[] certificates = null;
    byte[] content = null;
    byte[] hash = null;

    @Override
    public String getOID() {
        return identifier.getId();
    }

    @Override
    public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy, byte[] hash) {
        this.privateKey = privateKey;
        this.certificates = certificates;
        this.content = content;
        this.hash = hash;
    }

    @Override
    public Attribute getValue() throws SignerException {
        try {
            logger.debug(cadesMessagesBundle.getString("info.tsa.connecting"));

            if (timeStampGenerator != null) {
                  //Inicializa os valores para o timestmap
            	timeStampGenerator.initialize(content, privateKey, certificates, hash);

                //Obtem o carimbo de tempo atraves do servidor TSA
                byte[] response = timeStampGenerator.generateTimeStamp();

                //Valida o carimbo de tempo gerado
                timeStampGenerator.validateTimeStamp(content, response, hash);

                return new Attribute(identifier, new DERSet(ASN1Primitive.fromByteArray(response)));
            } else {
                throw new SignerException(cadesMessagesBundle.getString("error.tsa.not.found"));
            }
        } catch (SecurityException | IOException ex) {
            throw new SignerException(ex.getMessage());
        }
    }
}
