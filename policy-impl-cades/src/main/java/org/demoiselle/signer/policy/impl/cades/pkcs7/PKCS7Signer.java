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

import java.security.cert.Certificate;
import java.util.List;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.Signer;

/**
 * Basic specification for implementing digital signatures in PKCS7 Format.
 */
public interface PKCS7Signer extends Signer {

	/**
	 *  Assign a Certificate for validate or generate a signature
	 * @param certificate
	 */
    abstract public void setCertificates(Certificate certificate[]);

    /**
     * Assign a Policy for validate or generate a signature 
     * @param signaturePolicy
     */
    abstract public void setSignaturePolicy(Policies signaturePolicy);

    /**
     * 
     * Extracts the signed content from the digital signature structure, 
	 * if it is a signature with attached content.
     * 
     * @param signed signed content 
     * @param validate TRUE (to execute validation) or FALSE (not execute validation)
     * @return
     */
    abstract public byte[] getAttached(byte[] signed, boolean validate);
    
    /**
     * 
     * Generates a digital co-signature from a content, 
     * the result file does not contains the content that was signed
     * @param content
     * @param previewSigned CMS content from preview signed
     * @return
     */
    abstract public byte[] doDetachedSign (byte[] content, byte[] previewSigned);
    
    /**
     * Generates a digital co-signature from a content and attaches this content on result file
     * @param content
     * @param previewSigned CMS content from preview signed
     * @return
     */
    abstract public byte[] doAttachedSign(byte[] content, byte[] previewSigned);
    
    /**
     * Generates a digital couter-signature
     * @param previewCMSSignature CMS content from preview signed
     * @return new CMS Signature bytes
     */
    abstract public byte[] doCounterSign(byte[] previewCMSSignature);
    
    
    /**
     * 
     * Generates a digital signature from a previous calculated hash for a content, 
     * the result file does not contains the original content that was signed
     * @param hash
     * @return detached PCKS7 signature
     */
    abstract public byte[] doHashSign (byte[] hash);
    
    
    /**
     * Check a digital signature with attached content, informed by parameter signedData
     *
     * @param signedData
     * @return boolean
     * @deprecated use {@link checkAttachedSignature}
     */
    abstract public boolean checkAttached(byte[] signedData);
    
    
    /**
     * Check an digital detached signature, informed by parameter signedData and it's content
     *
     * @param content
     * @param signedData
     * @return boolean
     * @deprecated use {@link checkDetattachedSignature}
     */
    abstract public boolean checkDetattached(byte[] content, byte[] signedData);
    
    
    /**
     * Check a digital signature with attached content, informed by parameter signedData
     * @param signedData
     * @return List<SignatureInformations>
     */
    abstract public  List<SignatureInformations> checkAttachedSignature(byte[] signedData);
    
    /**
     * Check an digital detached signature, informed by parameter signedData and it's content
     * 
     * @param content
     * @param signedData
     * @return List<SignatureInformations>
     */
    
    abstract public  List<SignatureInformations> checkDetattachedSignature(byte[] content, byte[] signedData);
        
    
    /**
     * Check a digital detached signature, informed by parameter signedData, based on calculated hash from content
     * 
     * @param digestAlgorithmOID OID of algorithm used to calculate a hash from content (ex: 2.16.840.1.101.3.4.2.1 )
     * @param calculatedHashContent
     * @param signedData
     * @return List<SignatureInformations>
     */
    abstract public  List<SignatureInformations> checkSignatureByHash( String digestAlgorithmOID, byte[] calculatedHashContent, byte[] signedData);

    /**
     * get Signature Information for a checked signature
     * @return List<SignatureInformations>
     */
    abstract public List<SignatureInformations> getSignatureInfo();

    
 }