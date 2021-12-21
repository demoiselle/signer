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

package org.demoiselle.signer.core.timestamp;

import org.demoiselle.signer.core.exception.CertificateCoreException;

import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * Methods for generate a TimeStamp based on
 * Time Stamping Authority (TSA) service.
 * See <a href="https://datatracker.ietf.org/doc/html/rfc3161">RFC 3161</a>
 * for details.
 *
 * @author 07721825741
 */
public interface TimeStampGenerator {

	/**
	 * @param content      to be sign, if it is the parameter hash must to be null
	 * @param privateKey   authorized to use a TSA service
	 * @param certificates trusted chain
	 * @param hash         to be sign, if it is assigned the parameter content must to be null
	 * @throws CertificateCoreException exception
	 */
	void initialize(byte[] content, PrivateKey privateKey, Certificate[] certificates, byte[] hash) throws CertificateCoreException;

	/**
	 * @return timestamp
	 * @throws CertificateCoreException exception
	 */
	byte[] generateTimeStamp() throws CertificateCoreException;

	/**
	 * @param content  to be sign, if it is the parameter hash must to be null
	 * @param response signed timestamp from TSA
	 * @param hash     to be sign, if it is assigned the parameter content must to be null
	 * @throws CertificateCoreException exception
	 */
	void validateTimeStamp(byte[] content, byte[] response, byte[] hash) throws CertificateCoreException;

}
