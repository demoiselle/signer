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

package org.demoiselle.signer.policy.impl.cades;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;

import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.timestamp.Timestamp;

/**
 * Basic specification for implementation of Time Stamp on CADES format.
 */
public interface TimeStampCadesSigner {

	/**
	 * Generates a timestamp for a Digital Signature on CADES format,
	 * the result will contains the signature whith timestamp
	 *
	 * @param signature signature to be timestamped
	 * @return timestamped signature
	 */
	byte[] doTimeStampForSignature(byte[] signature);

	/**
	 * Generates a timestamp for a content
	 *
	 * @param content to be sign
	 * @return timeStamp timestamped content
	 */
	byte[] doTimeStampForContent(byte[] content);

	/**
	 * Generates a timestamp to a previous calculated hash from a content
	 *
	 * @param hash to be sign
	 * @return timeStamp timestamped hash
	 */
	byte[] doTimeStampFromHashContent(byte[] hash);

	/**
	 * Check a timestamp on CADES signature
	 *
	 * @param signature CADES signature
	 * @return list of timestamps
	 */
	List<Timestamp> checkTimeStampOnSignature(byte[] signature);

	/**
	 * Check a timestamp for a informed content
	 *
	 * @param timeStamp timestamp to check
	 * @param content   content related to timestamp
	 * @return Timestamp
	 */
	Timestamp checkTimeStampWithContent(byte[] timeStamp, byte[] content);

	/**
	 * Check a timestamp for a informed calculated hash from content
	 *
	 * @param timeStamp timestamp content
	 * @param hash      hash to check
	 * @return Timestamp
	 */
	Timestamp checkTimeStampWithHash(byte[] timeStamp, byte[] hash);

	/**
	 * Private key required for asymmetric cryptography
	 *
	 * @param privateKey set private key
	 */
	void setPrivateKey(PrivateKey privateKey);

	/**
	 * Assign a Certificate
	 *
	 * @param certificate set certificate
	 */
	void setCertificates(Certificate certificate[]);

	/**
	 * Set a signature policy
	 *
	 * @param signaturePolicy set signature policy
	 */
	void setSignaturePolicy(PolicyFactory.Policies signaturePolicy);
}
