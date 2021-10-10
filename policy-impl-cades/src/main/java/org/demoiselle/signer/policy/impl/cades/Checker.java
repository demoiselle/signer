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

import java.util.List;

/**
 * Basic specification for implementation of digital signatures in CADES format.
 */
public interface Checker {

	/**
	 * Check a digital signature with attached content, informed by parameter signedData
	 *
	 * @param signedData attached signature to be checked
	 * @return List&lt;SignatureInformations&gt; list of signature information
	 */
	List<SignatureInformations> checkAttachedSignature(byte[] signedData);

	/**
	 * Check an digital detached signature, informed by parameter signedData and it's content
	 *
	 * @param content    content to be checked
	 * @param signedData detached signature
	 * @return List&lt;SignatureInformations&gt; list of signature information
	 */

	List<SignatureInformations> checkDetachedSignature(byte[] content, byte[] signedData);

	/**
	 * Check a digital detached signature, informed by parameter signedData, based on calculated hash from content
	 *
	 * @param digestAlgorithmOID    OID of algorithm used to calculate a hash from content (ex: 2.16.840.1.101.3.4.2.1 )
	 * @param calculatedHashContent calculated hash
	 * @param signedData            detached signature
	 * @return List&lt;SignatureInformation&gt; list of signature information
	 */
	List<SignatureInformations> checkSignatureByHash(String digestAlgorithmOID, byte[] calculatedHashContent, byte[] signedData);
}
