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
import java.util.List;

/**
 * Basic specification for implementation of digital signatures in CADES format.
 */
public interface Signer {

    /**
     * Indicates which Provider will be used.
     *
     * @param provider
     */
    abstract public void setProvider(Provider provider);

    /**
     * Private key required for asymmetric cryptography
     *
     * @param privateKey
     */
    abstract public void setPrivateKey(PrivateKey privateKey);

    /**
     * Public key needed for asymmetric cryptography
     *
     * @param publicKey
     */
    abstract public void setPublicKey(PublicKey publicKey);

    /**
     * Set a Signature Algorithm. Ex: SHA256withRSA
     *
     * @param algorithm
     */
    abstract public void setAlgorithm(String algorithm);

    /**
     * Set an algorithm pre-defined in enumeration. Compatible with ICP-Brasil
     *
     * @param algorithm
     */
    abstract public void setAlgorithm(SignerAlgorithmEnum algorithm);

    /**
     * Generates a digital signature from a content and attaches this content on result file
     * @param content
     * @return
     */
    abstract public byte[] doAttachedSign(byte[] content);

    /**
     * 
     * Generates a digital signature from a content, 
     * the result file does not contains the content that was signed
     * @param content
     * @return
     */
    abstract public byte[] doDetachedSign (byte[] content);
    
    /**
     * Check if a digital signature, informed by parameter signedData, is valid for content
     *
     * @param content
     * @param signedData
     * @return
     * @deprecated use {@link checkAttached} or {@link checkDetached} or {@link checkOnlySignature}  
     */
    abstract public boolean check(byte[] content, byte[] signedData);

    
    /**
     * Check a digital signature with attached content, informed by parameter signedData
     *
     * @param signedData
     * @return
     */
    abstract public boolean checkAttached(byte[] signedData);
    
    
    /**
     * Check an digital detached signature, informed by parameter signedData and it's content
     *
     * @param content
     * @param signedData
     * @return
     */
    abstract public boolean checkDetattached(byte[] content, byte[] signedData);
    
    
    
    /**
     * Check a digital detached signature, informed by parameter signedData, based on calculated hash from content
     * 
     * @param digestAlgorithmOID OID of algorithm used to calculate a hash from content (ex: 2.16.840.1.101.3.4.2.1 )
     * @param calculatedHashContent
     * @param signedData
     * @return List<SignatureInfo>
    */
   abstract public List<SignatureInfo> checkSignatureByHash( String digestAlgorithmOID, byte[] calculatedHashContent, byte[] signedData);

    
    /**
     * Returns the provider.
     *
     * @return
     */
    abstract public Provider getProvider();

    /**
     * Returns the private key.
     *
     * @return
     */
    abstract public PrivateKey getPrivateKey();

    /**
     * Returns the algorithm to be used in the signature
     *
     * @return
     */
    abstract public String getAlgorithm();

    /**
     * Returns the public key.
     *
     * @return
     */
    abstract public PublicKey getPublicKey();

    /**
     * 
     * Generates a digital signature from a previous calculated hash for a content, 
     * the result file does not contains the original content that was signed
     * @param hash
     * @return detached PCKS7 signature
     */
    abstract public byte[] doHashSign (byte[] hash);
}
