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
import java.security.Provider;
import java.security.PublicKey;
import java.util.Date;

import org.bouncycastle.cms.CMSSignedData;

/**
 * Basic specification for implementation of digital signatures in CADES format.
 */
public interface Signer {

	/**
	 * Indicates which Provider will be used.
	 *
	 * @param provider provider to be used
	 */
	void setProvider(Provider provider);

	/**
	 * Private key required for asymmetric cryptography
	 *
	 * @param privateKey private key to be used
	 */
	void setPrivateKey(PrivateKey privateKey);

	/**
	 * Public key needed for asymmetric cryptography
	 *
	 * @param publicKey public key to be used
	 */
	void setPublicKey(PublicKey publicKey);

	/**
	 * Set a Signature Algorithm. Ex: SHA256withRSA
	 *
	 * @param algorithm algorithm to be used
	 */
	void setAlgorithm(String algorithm);

	/**
	 * Set an algorithm pre-defined in enumeration. Compatible with ICP-Brasil
	 *
	 * @param algorithm algorithm representation to be used
	 */
	void setAlgorithm(SignerAlgorithmEnum algorithm);

	/**
	 * Generates a digital signature from a content and attaches this content on result file
	 *
	 * @param content content to be signed
	 * @return attached signature
	 */
	byte[] doAttachedSign(byte[] content);

	/**
	 * Generates a digital signature from a content,
	 * the result does not contains the content that was signed
	 *
	 * @param content content to be signed
	 * @return detached signature
	 */
	byte[] doDetachedSign(byte[] content);
	
	/**
	 * Returns the provider.
	 *
	 * @return current provider
	 */
	Provider getProvider();

	/**
	 * Returns the private key.
	 *
	 * @return current private key
	 */
	PrivateKey getPrivateKey();

	/**
	 * Returns the algorithm to be used in the signature
	 *
	 * @return current algorithm
	 */
	String getAlgorithm();

	/**
	 * Returns the public key.
	 *
	 * @return current public key
	 */
	PublicKey getPublicKey();

	/**
	 * Generates a digital signature from a previous calculated hash for a content,
	 * the result file does not contains the original content that was signed
	 *
	 * @param hash hash to be signed
	 * @return detached PCKS7 signature
	 */
	byte[] doHashSign(byte[] hash);

	/**
	 * Private key required for sign timestamp request
	 *
	 * @param privateKey to be used for request timestamp
	 */
	void setPrivateKeyForTimeStamp(PrivateKey privateKey);

	/**
	 * @return privateKey to be used for request timestamp
	 */
	PrivateKey getPrivateKeyForTimeStamp();

	/**
	 * Data of end of Certificate use.
	 *
	 * @return Date of end certificate use.
	 */
	Date getNotAfterSignerCertificate();

	/**
	 * @return who perform the signature
	 */
	String getSignatory();
	
	/**
	 * 
	 * Prepare to Generates a digital signature from a content,
	 * the result does not contains the content that was signed
	 * On this step only signed attributes are generates
	 * 
	 * @param content full content to sign
	 * @return only signed attributes
	 */
	CMSSignedData prepareDetachedSign(byte[] content);
	
	
	/**
	 * Prepare to Generates a digital signature from a content and attaches this content on result
	 * On this step only signed attributes are generates
	 *
	 * @param content content to be signed
	 * @return only signed attributes for attached signature
	 */
	CMSSignedData prepareAttachedSign(byte[] content);

	
	
	/**
	 * Prepare to Generates a digital signature from a previous calculated hash for a content,
	 * the result does not contains the original content that was signed
	 * On this step only signed attributes are generates
	 *
	 * @param hash hash to be signed
	 * @return only signed attributes for detached PCKS7 signature
	 */
	CMSSignedData prepareHashSign(byte[] hash);
	
	
	
	/**
	 * 
	 * Generates a digital signature from a content,
	 * the result does not contains the content that was signed
	 * On this step only signed attributes are generates
	 * 
	 * @param signedData signed attributes
	 * @return only signed attributes
	 */
	byte[] envelopDetachedSign(CMSSignedData signedData);
	
	
	/**
	 * Generates a digital signature from a content and attaches this content on result
	 * On this step only signed attributes are generates
	 *
	 * @param signedData signed attributes
	 * @return only signed attributes for attached signature
	 */
	byte[] envelopAttachedSign(CMSSignedData signedData);

	
	
	/**
	 * Generates a digital signature from a previous calculated hash for a content,
	 * the result does not contains the original content that was signed
	 * On this step only signed attributes are generates
	 *
	 * @param signedData signed attributes
	 * @return only signed attributes for detached PCKS7 signature
	 */
	byte[] envelopHashSign(CMSSignedData signedData);
	
}
