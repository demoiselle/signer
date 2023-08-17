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

package org.demoiselle.signer.policy.impl.cades.pkcs7;

import java.util.List;

import org.demoiselle.signer.policy.impl.cades.AttachedContentValidation;
import org.demoiselle.signer.policy.impl.cades.Checker;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;

/**
 * Basic specification for implementing digital signatures in PKCS7 Format.
 */
public interface PKCS7Checker extends Checker {

	/**
	 * Extracts the signed content from the digital signature structure,
	 * if it is a signature with attached content.
	 *
	 * @param signed   signed content
	 * @param validate TRUE (to execute validation) or FALSE (not execute validation)
	 * @return signed content
	 */
	AttachedContentValidation getAttached(byte[] signed, boolean validate);

	/**
	 * Check a digital signature with attached content, informed by parameter signedData
	 *
	 * @param signedData attached signature to be checked
	 * @return List&lt;SignatureInformations&gt; list of signature informations
	 */
	List<SignatureInformations> checkAttachedSignature(byte[] signedData);

	/**
	 * Check a digital detached signature, informed by parameter signedData, based on calculated hash from content
	 *
	 * @param digestAlgorithmOID    OID of algorithm used to calculate a hash from content (ex: 2.16.840.1.101.3.4.2.1 )
	 * @param calculatedHashContent calculated hash
	 * @param signedData            detached signature
	 * @return List&lt;SignatureInformations&gt; list of signature informations
	 */
	List<SignatureInformations> checkSignatureByHash(String digestAlgorithmOID, byte[] calculatedHashContent, byte[] signedData);

	/**
	 * get Signature Information for a checked signature
	 *
	 * @return List&lt;SignatureInformations&gt;
	 */
	List<SignatureInformations> getSignaturesInfo();
	
	
	/**
	 * Check a digital detached signature, informed by parameter signedData, based on calculated hash from content
	 *
	 * @param calculatedHashContent calculated hash
	 * @param signedData            detached signature
	 * @return List&lt;SignatureInformations&gt; list of signature informations
	 */
	List<SignatureInformations> checkSignatureByHash(byte[] calculatedHashContent, byte[] signedData);

}
