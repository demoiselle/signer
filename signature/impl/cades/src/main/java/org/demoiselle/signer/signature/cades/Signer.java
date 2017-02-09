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
package org.demoiselle.signer.signature.cades;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

/**
 * Especificação básica para implementação de assinaturas digitais no formato CADES.
 */
public interface Signer {

    /**
     * Indica qual o Provider será utilizado.
     *
     * @param provider
     */
    abstract public void setProvider(Provider provider);

    /**
     * Chave privada necessária para a criptografia assimétrica
     *
     * @param privateKey
     */
    abstract public void setPrivateKey(PrivateKey privateKey);

    /**
     * Chave publica necessária para a criptografia assimétrica
     *
     * @param publicKey
     */
    abstract public void setPublicKey(PublicKey publicKey);

    /**
     * Algoritmo de Assinatura. Ex: SHA1withRSA
     *
     * @param algorithm
     */
    abstract public void setAlgorithm(String algorithm);

    /**
     * Algoritmo pré-defido no enum. Compatíveis com ICP-Brasil
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
     */
    abstract public boolean check(byte[] content, byte[] signedData);

    /**
     * Retorna o provider.
     *
     * @return
     */
    abstract public Provider getProvider();

    /**
     * Retorna a chave privada.
     *
     * @return
     */
    abstract public PrivateKey getPrivateKey();

    /**
     * Retorna o algoritmo.
     *
     * @return
     */
    abstract public String getAlgorithm();

    /**
     * Retorna a chave publica.
     *
     * @return
     */
    abstract public PublicKey getPublicKey();

}
