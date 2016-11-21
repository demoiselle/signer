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
package org.demoiselle.signer.signature.core;

import org.demoiselle.signer.signature.core.exception.CertificateCoreException;

import java.io.File;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * Carregamento de Certificados Digitais.
 */
public interface CertificateLoader {

    /**
     * Obtem o certificado A1 a partir de um arquivo
     *
     * @param file O arquivo que contém o certificado
     * @return O certificado carregado
     * @throws CertificateCoreException Retorna a exceção
     * CertificateCoreException
     */
    public X509Certificate load(File file) throws CertificateCoreException;

    /**
     * Obtem o certificado A3 a partir de um Token /Smartcard
     *
     * @return O certificado carregado
     * @throws CertificateCoreException Retorna a exceção
     * CertificateCoreException
     */
    public X509Certificate loadFromToken() throws CertificateCoreException;

    /**
     * Obtem o certificado A3 a partir de um Token /Smartcard
     *
     * @param pinNumber O pin do dispositivo
     * @return O certificado carregado
     * @throws CertificateCoreException Retorna a exceção
     * CertificateCoreException
     */
    public X509Certificate loadFromToken(String pinNumber) throws CertificateCoreException;

    /**
     * Obtem o certificado A3 a partir de um Token /Smartcard
     *
     * @param pinNumber O pin do dispositivo
     * @param alias O apelido associado ao certificado
     * @return O certificado carregado
     * @throws CertificateCoreException Retorna a exceção
     * CertificateCoreException
     */
    public X509Certificate loadFromToken(String pinNumber, String alias) throws CertificateCoreException;

    /**
     * Associa um keystore previamente existente
     *
     * @param keyStore O keystore fornecido
     * @throws CertificateCoreException Retorna a exceção
     * CertificateCoreException
     */
    public void setKeyStore(KeyStore keyStore) throws CertificateCoreException;

    /**
     * Retorna o KeyStore utilizado pelo {@link CertificateLoader}.
     *
     * @return keyStore O keystore fornecido
     * @throws CertificateCoreException Retorna a exceção
     * CertificateCoreException
     */
    public KeyStore getKeyStore() throws CertificateCoreException;

}
