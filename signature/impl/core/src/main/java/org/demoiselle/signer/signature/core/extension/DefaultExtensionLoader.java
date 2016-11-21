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
package org.demoiselle.signer.signature.core.extension;

import org.demoiselle.signer.signature.core.IOIDExtensionLoader;
import org.demoiselle.signer.signature.core.exception.CertificateCoreException;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.cert.X509Certificate;

public class DefaultExtensionLoader implements IOIDExtensionLoader {

    @Override
    public void load(Object object, Field field, X509Certificate x509) {
        if (field.isAnnotationPresent(DefaultExtension.class)) {
            DefaultExtension annotation = field.getAnnotation(DefaultExtension.class);

            Object keyValue;

            BasicCertificate basicCertificate = new BasicCertificate(x509);

            switch (annotation.type()) {
                case CRL_URL:
                    try {
                        keyValue = basicCertificate.getCRLDistributionPoint();
                    } catch (IOException e1) {
                        throw new CertificateCoreException("Error on get value to field " + field.getName(), e1);
                    }
                    break;
                case SERIAL_NUMBER:
                    keyValue = basicCertificate.getSerialNumber();
                    break;
                case ISSUER_DN:
                    try {
                        keyValue = basicCertificate.getCertificateIssuerDN().toString();
                    } catch (IOException e1) {
                        throw new CertificateCoreException("Error on get value to field " + field.getName(), e1);
                    }
                    break;
                case SUBJECT_DN:
                    try {
                        keyValue = basicCertificate.getCertificateSubjectDN().toString();
                    } catch (IOException e1) {
                        throw new CertificateCoreException("Error on get value to field " + field.getName(), e1);
                    }
                    break;
                case KEY_USAGE:
                    keyValue = basicCertificate.getICPBRKeyUsage().toString();
                    break;
                case PATH_LENGTH:
                    keyValue = basicCertificate.getPathLength();
                    break;
                case AUTHORITY_KEY_IDENTIFIER:
                    try {
                        keyValue = basicCertificate.getAuthorityKeyIdentifier();
                    } catch (IOException e1) {
                        throw new CertificateCoreException("Error on get value to field " + field.getName(), e1);
                    }
                    break;

                case SUBJECT_KEY_IDENTIFIER:
                    try {
                        keyValue = basicCertificate.getSubjectKeyIdentifier();
                    } catch (IOException e1) {
                        throw new CertificateCoreException("Error on get value to field " + field.getName(), e1);
                    }
                    break;

                case BEFORE_DATE:
                    keyValue = basicCertificate.getBeforeDate();
                    break;
                case AFTER_DATE:
                    keyValue = basicCertificate.getAfterDate();
                    break;
                case CERTIFICATION_AUTHORITY:
                    keyValue = basicCertificate.isCertificadoAc();
                    break;

                default:
                    throw new CertificateCoreException(annotation.type() + " Not Implemented");
            }

            try {
                field.setAccessible(true);
                field.set(object, keyValue);
            } catch (IllegalAccessException | IllegalArgumentException | SecurityException e) {
                throw new CertificateCoreException("Error on load value in field " + field.getName(), e);
            }
        }
    }

}
