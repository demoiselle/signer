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
package org.demoiselle.signer.signature.signer.pkcs1.impl;

import org.demoiselle.signer.signature.signer.SignerAlgorithmEnum;
import org.demoiselle.signer.signature.signer.SignerException;
import org.demoiselle.signer.signature.signer.pkcs1.PKCS1Signer;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class PKCS1SignerImpl implements PKCS1Signer {

    private Provider provider = null;
    private PrivateKey privateKey = null;
    private String algorithm = SignerAlgorithmEnum.SHA1withRSA.getAlgorithm();
    private PublicKey publicKey = null;

    /**
     * Realiza a assinatura utilizando a API Java Utiliza o algoritmo da
     * propriedade algorithm. Caso essa propriedade não esteja setada, o
     * algoritmo do enum {@link SignerAlgorithmEnum.DEFAULT} será usado. Para
     * este método é necessário informar o conteúdo e a chave privada.
     *
     * @param content Conteúdo a ser assinado.
     */
    @Override
    public byte[] doSign(byte[] content) {
        if (content == null) {
            throw new SignerException("O conteudo é nulo.");
        }
        if (this.privateKey == null) {
            throw new SignerException("A chave privada é nula.");
        }
        if (this.algorithm == null) {
            this.algorithm = SignerAlgorithmEnum.DEFAULT.getAlgorithm();
        }

        Signature sign = null;
        byte[] result = null;
        try {
            if (this.provider != null) {
                sign = Signature.getInstance(this.algorithm, this.provider);
            } else {
                sign = Signature.getInstance(this.algorithm);
            }

            sign.initSign(this.privateKey);
            sign.update(content);

            result = sign.sign();

        } catch (NoSuchAlgorithmException exception) {
            throw new SignerException("Error on load algorithm " + algorithm, exception);
        } catch (InvalidKeyException exception) {
            throw new SignerException("Invalid key", exception);
        } catch (SignatureException exception) {
            throw new SignerException("Signature error", exception);
        }
        return result;
    }

    /**
     * Realiza a checagem de um conteúdo assinado utilizando a API Java. É
     * necessário informar o conteúdo original e o assinado para a verificação.
     * Utiliza o algoritmo da propriedade algorithm. Caso essa propriedade não
     * esteja setada, o algoritmo do enum {@link SignerAlgorithmEnum.DEFAULT}
     * será usado. Para este método é necessário informar o conteúdo original,
     * conteúdo assinado e a chave pública.
     *
     * @param content Conteúdo original a ser comparado com o conteúdo assinado.
     * @param signed Conteúdo assinado a ser verificado.
     */
    @Override
    public boolean check(byte[] content, byte[] signed) {
        if (content == null) {
            throw new SignerException("O conteúdo é nulo.");
        }
        if (signed == null) {
            throw new SignerException("O conteúdo assinado é nulo.");
        }
        if (this.publicKey == null) {
            throw new SignerException("A chave pública é nula.");
        }
        if (this.algorithm == null) {
            this.algorithm = SignerAlgorithmEnum.DEFAULT.getAlgorithm();
        }

        Signature signature = null;
        boolean result = false;

        try {
            if (this.provider != null) {
                signature = Signature.getInstance(this.algorithm, this.provider);
            } else {
                signature = Signature.getInstance(this.algorithm);
            }

            signature.initVerify(this.publicKey);
            signature.update(content);

            result = signature.verify(signed);

        } catch (NoSuchAlgorithmException exception) {
            throw new SignerException("Error on load algorithm " + this.algorithm, exception);
        } catch (InvalidKeyException exception) {
            throw new SignerException("Invalid key", exception);
        } catch (SignatureException exception) {
            throw new SignerException("Signature error", exception);
        }

        return result;
    }

    @Override
    public void setProvider(Provider provider) {
        this.provider = provider;
    }

    @Override
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public void setAlgorithm(SignerAlgorithmEnum algorithm) {
        this.algorithm = algorithm.getAlgorithm();
    }

    @Override
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public Provider getProvider() {
        return this.provider;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public PublicKey getPublicKey() {
        return this.publicKey;
    }

}
