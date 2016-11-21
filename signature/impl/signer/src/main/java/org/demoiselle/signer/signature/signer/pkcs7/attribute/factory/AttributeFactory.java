/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
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
package org.demoiselle.signer.signature.signer.pkcs7.attribute.factory;

import org.demoiselle.signer.signature.signer.pkcs7.attribute.SignedOrUnsignedAttribute;

import java.util.ServiceLoader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AttributeFactory {

    private static final Logger logger = LoggerFactory.getLogger(AttributeFactory.class);

    public static final AttributeFactory instance = new AttributeFactory();

    public static AttributeFactory getInstance() {
        return AttributeFactory.instance;
    }

    public SignedOrUnsignedAttribute factory(String attributeOID) {
        logger.info("Consultando o atributo com OID [{}]", attributeOID);
        ServiceLoader<SignedOrUnsignedAttribute> loader = ServiceLoader.load(SignedOrUnsignedAttribute.class);
        if (loader != null) {
            for (SignedOrUnsignedAttribute attribute : loader) {
                if (attribute.getOID().equalsIgnoreCase(attributeOID)) {
                    logger.info("Retornando o atributo {}", attribute.getClass().getName());
                    return attribute;
                }
            }
        } else {
            logger.info("Atributo com OID [{}] nao foi localizado.", attributeOID);
        }
        return null;
    }

}
