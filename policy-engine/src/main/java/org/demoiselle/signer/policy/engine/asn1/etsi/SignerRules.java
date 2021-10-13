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

package org.demoiselle.signer.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;

/**
 * The signer rules identify:
 * <ul>
 * <li>if the eContent is empty and the signature is calculated using
 * a hash of signed data external to CMS structure;</li>
 * <li>the CMS signed attributes that shall be provided by the signer
 * under this policy;</li>
 * <li>the CMS unsigned attribute that shall be provided by the signer
 * under this policy;</li>
 * <li>whether the certificate identifiers from the full certification
 * path up to the trust point shall be provided by the signer in the
 * SigningCertificate attribute;</li>
 * <li>whether a signer's certificate, or all certificates in the
 * certification path to the trust point shall be provided by the signer
 * in the certificates field of SignedData.</li>
 * </ul>
 *
 * <pre>
 * SignerRules ::= SEQUENCE {
 *     externalSignedData BOOLEAN OPTIONAL,
 *     -- True if signed data is external to CMS structure
 *     -- False if signed data part of CMS structure
 *     -- not present if either allowed
 *     mandatedSignedAttr {@link CMSAttrs},
 *     -- Mandated CMS signed attributes
 *     mandatedUnsignedAttr {@link CMSAttrs},
 *     -- Mandated CMS unsigned attributed
 *     mandatedCertificateRef [0] {@link CertRefReq} DEFAULT signerOnly,
 *     -- Mandated Certificate Reference
 *     mandatedCertificateInfo [1] {@link CertInfoReq} DEFAULT none,
 *     -- Mandated Certificate Info
 *     signPolExtensions [2]{@link SignPolExtensions} OPTIONAL
 *     }
 *
 * CMSAttrs ::= SEQUENCE OF OBJECT IDENTIFIER *
 * </pre>
 *
 * @see ASN1Boolean
 * @see ASN1Encodable
 * @see ASN1Sequence
 * @see ASN1Primitive
 * @see DERSequence
 * @see DERTaggedObject
 */
public class SignerRules extends ASN1Object {

	private Boolean externalSignedData = null;

	/* Mandated CMS signed attributes */
	private CMSAttrs mandatedSignedAttr;

	/* Mandated CMS unsigned attributed */
	private CMSAttrs mandatedUnsignedAttr;

	/* Mandated Certificate Reference */
	private CertRefReq mandatedCertificateRef = CertRefReq.signerOnly;

	/* Mandated Certificate Info */
	private CertInfoReq mandatedCertificateInfo = CertInfoReq.none;

	private SignPolExtensions signPolExtensions;

	public Boolean getExternalSignedData() {
		return externalSignedData;
	}

	public void setExternalSignedData(Boolean externalSignedData) {
		this.externalSignedData = externalSignedData;
	}

	public CMSAttrs getMandatedSignedAttr() {
		return mandatedSignedAttr;
	}

	public void setMandatedSignedAttr(CMSAttrs mandatedSignedAttr) {
		this.mandatedSignedAttr = mandatedSignedAttr;
	}

	public CMSAttrs getMandatedUnsignedAttr() {
		return mandatedUnsignedAttr;
	}

	public void setMandatedUnsignedAttr(CMSAttrs mandatedUnsignedAttr) {
		this.mandatedUnsignedAttr = mandatedUnsignedAttr;
	}

	public CertRefReq getMandatedCertificateRef() {
		return mandatedCertificateRef;
	}

	public void setMandatedCertificateRef(CertRefReq mandatedCertificateRef) {
		this.mandatedCertificateRef = mandatedCertificateRef;
	}

	public CertInfoReq getMandatedCertificateInfo() {
		return mandatedCertificateInfo;
	}

	public void setMandatedCertificateInfo(CertInfoReq mandatedCertificateInfo) {
		this.mandatedCertificateInfo = mandatedCertificateInfo;
	}

	public SignPolExtensions getSignPolExtensions() {
		return signPolExtensions;
	}

	public void setSignPolExtensions(SignPolExtensions signPolExtensions) {
		this.signPolExtensions = signPolExtensions;
	}

	@Override
	public void parse(ASN1Primitive primitive) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(primitive);

		int total = derSequence.size();
		if (total > 0) {
			for (int i = 0; i < total; i++) {
				ASN1Primitive object = derSequence.getObjectAt(i).toASN1Primitive();
				if (object instanceof DERTaggedObject) {
					DERTaggedObject derTaggedObject = (DERTaggedObject) object;
					TAG tag = TAG.getTag(derTaggedObject.getTagNo());
					switch (tag) {
						case mandatedCertificateRef:
							this.mandatedCertificateRef = CertRefReq.parse(object);
							break;
						case mandatedCertificateInfo:
							this.mandatedCertificateInfo = CertInfoReq.parse(object);
							break;
						case signPolExtensions:
							this.signPolExtensions = new SignPolExtensions();
							this.signPolExtensions.parse(object);
							break;
						default:
							break;
					}
				}
			}
		}

		int i = 0;
		ASN1Encodable object = derSequence.getObjectAt(i);
		if (!(object instanceof DERSequence)) {
			if (object instanceof ASN1Boolean) {
				this.externalSignedData = ((ASN1Boolean) object).isTrue();
			}
			i++;
		}
		this.mandatedSignedAttr = new CMSAttrs();
		this.mandatedSignedAttr.parse(derSequence.getObjectAt(i).toASN1Primitive());
		i++;
		this.mandatedUnsignedAttr = new CMSAttrs();
		this.mandatedUnsignedAttr.parse(derSequence.getObjectAt(i).toASN1Primitive());
	}

	enum TAG {

		mandatedCertificateRef(0),
		mandatedCertificateInfo(1),
		signPolExtensions(2);

		private int value;

		TAG(int value) {
			this.value = value;
		}

		public static TAG getTag(int value) {
			for (TAG tag : TAG.values()) {
				if (tag.value == value) {
					return tag;
				}
			}
			return null;
		}
	}

}
