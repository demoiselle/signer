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

package org.demoiselle.signer.policy.impl.cades.pkcs1.impl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cms.CMSSignedData;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.pkcs1.PKCS1Signer;

/**
 * Basic implementation of digital signatures in PKCS1 format.
 */
public class PKCS1SignerImpl implements PKCS1Signer {

	public PKCS1SignerImpl() {
		super();

	}

	private Provider provider = null;
	private PrivateKey privateKey = null;
	private String algorithm = SignerAlgorithmEnum.SHA512withRSA.getAlgorithm();
	private PublicKey publicKey = null;
	private static MessagesBundle cadesMessagesBundle = new MessagesBundle();
	private PrivateKey privateKeyForTimeStamp = null;

	/**
	 * Performs the signature using the Java API.
	 * It uses the algorithm value on property: algorithm.
	 * If this property is not set, the {@link SignerAlgorithmEnum#DEFAULT} enumeration algorithm
	 * will be used.
	 * For this method it is necessary to inform the content and the private key.
	 *
	 * @param content Content to be signed.
	 */
	public byte[] doSign(byte[] content) {
		if (content == null) {
			throw new SignerException(cadesMessagesBundle.getString("error.value.null"));
		}
		if (this.privateKey == null) {
			throw new SignerException(cadesMessagesBundle.getString("error.private.key.null"));
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
			throw new SignerException(cadesMessagesBundle.getString("error.load.algorithm", algorithm), exception);
		} catch (InvalidKeyException exception) {
			throw new SignerException(cadesMessagesBundle.getString("error.private.key.invalid"), exception);
		} catch (SignatureException exception) {
			throw new SignerException(cadesMessagesBundle.getString("error.sign.exception"), exception);
		}
		return result;
	}

	/**
	 * Performs checking for signed content using the Java API.
	 * You must enter the original content and signature for
	 * verification. It uses the value algorithm of property:
	 * algorithm. If this property is not set, the
	 * {@link SignerAlgorithmEnum#DEFAULT} enumeration algorithm
	 * will be used. For this method it is necessary to inform the
	 * original content, signed content and the public key.
	 *
	 * @param content Original content to be compared to signed content.
	 * @param signed  Signed content to be verified.
	 *
	 * @return {@code true} if and only if content was correctly
	 * verified.
	 */
	public boolean check(byte[] content, byte[] signed) {
		if (content == null) {
			throw new SignerException(cadesMessagesBundle.getString("error.value.null"));
		}
		if (signed == null) {
			throw new SignerException(cadesMessagesBundle.getString("error.content.signed.null"));
		}
		if (this.publicKey == null) {
			throw new SignerException(cadesMessagesBundle.getString("error.public.key.null"));
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
			throw new SignerException(cadesMessagesBundle.getString("error.load.algorithm", this.algorithm), exception);
		} catch (InvalidKeyException exception) {
			throw new SignerException(cadesMessagesBundle.getString("error.public.key.invalid"), exception);
		} catch (SignatureException exception) {
			throw new SignerException(cadesMessagesBundle.getString("error.check.exception"), exception);
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

	@Override
	public byte[] doAttachedSign(byte[] content) {
		return this.doSign(content);
	}

	@Override
	public byte[] doDetachedSign(byte[] content) {
		return this.doSign(content);
	}

	//TODO não implementado
	@Override
	public byte[] doHashSign(byte[] hash) {
		return null;
	}

	public boolean checkAttached(byte[] signedData) {
		//TODO não implementado
		return false;
	}


	public List<SignatureInformations> checkSignatureByHash(String digestAlgorithm, byte[] calculatedHashContent, byte[] signedData) {
		//TODO não implementado
		return null;
	}

	public List<SignatureInformations> checkAttachedSignature(byte[] signedData) {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public void setPrivateKeyForTimeStamp(PrivateKey privateKeyToTimeStamp) {
		this.privateKeyForTimeStamp = privateKeyToTimeStamp;

	}

	@Override
	public PrivateKey getPrivateKeyForTimeStamp() {
		return privateKeyForTimeStamp;
	}

	@Override
	public Date getNotAfterSignerCertificate() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getSignatory() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CMSSignedData prepareDetachedSign(byte[] content) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CMSSignedData prepareAttachedSign(byte[] content) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CMSSignedData prepareHashSign(byte[] hash) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] envelopDetachedSign(CMSSignedData signedData) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] envelopAttachedSign(CMSSignedData signedData) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] envelopHashSign(CMSSignedData signedData) {
		// TODO Auto-generated method stub
		return null;
	}

}
