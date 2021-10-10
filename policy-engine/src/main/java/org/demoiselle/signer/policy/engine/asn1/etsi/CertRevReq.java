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

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;

/**
 * The RevocRequirements field specifies minimum requirements for revocation information,
 * obtained through CRLs and/or OCSP responses,
 * to be used in checking the revocation status of certificates.
 * This ASN1 structure is used to define policy for validating the signing certificate,
 * the TSA's certificate and attribute certificates
 * <p>
 * Certificate revocation requirements are specified in terms of checks required on:
 * endCertRevReq {@link RevReq } : end certificates (i.e. the signers certificate,
 * the attribute certificate or the timestamping authority certificate);
 * caCerts  {@link RevReq }: CA certificates.
 */
public class CertRevReq extends ASN1Object {

	private RevReq endCertRevReq;
	private RevReq caCerts;

	public RevReq getEndCertRevReq() {
		return endCertRevReq;
	}

	public void setEndCertRevReq(RevReq endCertRevReq) {
		this.endCertRevReq = endCertRevReq;
	}

	public RevReq getCaCerts() {
		return caCerts;
	}

	public void setCaCerts(RevReq caCerts) {
		this.caCerts = caCerts;
	}

	@Override
	public void parse(ASN1Primitive derObject) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);

		this.endCertRevReq = new RevReq();
		this.endCertRevReq.parse(derSequence.getObjectAt(0).toASN1Primitive());

		this.caCerts = new RevReq();
		this.caCerts.parse(derSequence.getObjectAt(1).toASN1Primitive());
	}
}
