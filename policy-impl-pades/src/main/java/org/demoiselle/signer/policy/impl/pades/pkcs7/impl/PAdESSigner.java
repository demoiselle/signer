/*
 * Demoiselle Framework
 * Copyright (C) 2021 SERPRO
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

package org.demoiselle.signer.policy.impl.pades.pkcs7.impl;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;

import org.bouncycastle.cms.CMSSignedData;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESSigner;
import org.demoiselle.signer.policy.impl.pades.pkcs7.PCKS7Signer;

public class PAdESSigner implements PCKS7Signer {

	private CAdESSigner cAdESSigner;

	public PAdESSigner() {
		cAdESSigner = new CAdESSigner(null, Policies.AD_RB_PADES_1_1, true);
	}

	public PAdESSigner(Policies police) {
		cAdESSigner = new CAdESSigner(null, police, true);
	}

	public PAdESSigner(String algorithm, Policies police) {
		cAdESSigner = new CAdESSigner(algorithm, police, true);
	}

	@Override
	public void setProvider(Provider provider) {
		cAdESSigner.setProvider(provider);
	}

	@Override
	public void setPrivateKey(PrivateKey privateKey) {
		cAdESSigner.setPrivateKey(privateKey);
	}

	@Override
	public void setPublicKey(PublicKey publicKey) {
		cAdESSigner.setPublicKey(publicKey);
	}

	@Override
	public void setAlgorithm(String algorithm) {
		cAdESSigner.setAlgorithm(algorithm);
	}

	@Override
	public void setAlgorithm(SignerAlgorithmEnum algorithm) {
		cAdESSigner.setAlgorithm(algorithm);
	}

	/*
	 * Not for PAdES.
	 * @param content
	 * @return null
	 */
	@Override
	public byte[] doAttachedSign(byte[] content) {
		return null;
	}

	@Override
	public byte[] doDetachedSign(byte[] content) {
		return cAdESSigner.doDetachedSign(content);
	}

	@Override
	public Provider getProvider() {
		return cAdESSigner.getProvider();
	}

	@Override
	public PrivateKey getPrivateKey() {
		return cAdESSigner.getPrivateKey();
	}

	@Override
	public String getAlgorithm() {
		return cAdESSigner.getAlgorithm();
	}

	@Override
	public PublicKey getPublicKey() {
		return cAdESSigner.getPublicKey();
	}

	@Override
	public byte[] doHashSign(byte[] hash) {
		return cAdESSigner.doHashSign(hash);
	}

	@Override
	public void setCertificates(Certificate[] certificate) {
		cAdESSigner.setCertificates(certificate);
	}

	@Override
	public void setSignaturePolicy(Policies signaturePolicy) {
		cAdESSigner.setSignaturePolicy(signaturePolicy);
	}

	@Override
	public void setCertificatesForTimeStamp(Certificate[] certificates) {
		cAdESSigner.setCertificatesForTimeStamp(certificates);
	}

	@Override
	public void setPrivateKeyForTimeStamp(PrivateKey privateKeyForTimeStamp) {
		cAdESSigner.setPrivateKeyForTimeStamp(privateKeyForTimeStamp);
	}

	@Override
	public PrivateKey getPrivateKeyForTimeStamp() {
		return cAdESSigner.getPrivateKeyForTimeStamp();
	}

	@Override
	public Date getNotAfterSignerCertificate() {
		return cAdESSigner.getNotAfterSignerCertificate();
	}

	@Override
	public String getSignatory() {
		return cAdESSigner.getSignatory();
	}

	@Override
	public CMSSignedData prepareDetachedSign(byte[] content) {
		return cAdESSigner.prepareDetachedSign(content);
	}

	
	/*
	 * Not for PAdES.
	 * @param content
	 * @return null
	 */
	@Override
	public CMSSignedData prepareAttachedSign(byte[] content) {
		return null;
	}

	@Override
	public CMSSignedData prepareHashSign(byte[] hash) {
		return cAdESSigner.prepareHashSign(hash);
	}

	@Override
	public byte[] envelopDetachedSign(CMSSignedData signedData) {
		return cAdESSigner.envelopDetachedSign(signedData);
	}

	/*
	 * Not for PAdES.
	 * @param content
	 * @return null
	 */
	@Override
	public byte[] envelopAttachedSign(CMSSignedData signedData) {
		return null;
	}
	
	@Override
	public byte[] envelopHashSign(CMSSignedData signedData) {
		return cAdESSigner.envelopHashSign(signedData);
	}
}
