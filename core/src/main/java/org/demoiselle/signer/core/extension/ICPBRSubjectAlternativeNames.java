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

package org.demoiselle.signer.core.extension;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

/**
 * ICP-BRASIL's definitions of Subject Alternative Names.
 */
public class ICPBRSubjectAlternativeNames {

	private String email = null;
	private String dns = null;
	private ICPBRCertificatePF icpBrCertPF = null;
	private ICPBRCertificatePJ icpBrCertPJ = null;
	private ICPBRCertificateEquipment icpBrCertEquipment = null;

	/**
	 * @param certificate -&gt; X509Certificate
	 * @see java.security.cert.X509Certificate
	 */
	public ICPBRSubjectAlternativeNames(X509Certificate certificate) {

		String SN = getSNfromCertificate(certificate);
		CertificateExtra ce = new CertificateExtra(certificate);

		if (ce.isCertificatePF()) {
			icpBrCertPF = new ICPBRCertificatePF(ce.getOID_2_16_76_1_3_1(), ce.getOID_2_16_76_1_3_5(), ce.getOID_2_16_76_1_3_6());
		} else if (ce.isCertificatePJ()) {
			icpBrCertPJ = new ICPBRCertificatePJ(ce.getOID_2_16_76_1_3_2(), ce.getOID_2_16_76_1_3_3(), ce.getOID_2_16_76_1_3_4(), ce.getOID_2_16_76_1_3_7());
		} else if (ce.isCertificateEquipment()) {
			icpBrCertEquipment = new ICPBRCertificateEquipment(ce.getOID_2_16_76_1_3_2(), ce.getOID_2_16_76_1_3_3(), ce.getOID_2_16_76_1_3_4(), ce.getOID_2_16_76_1_3_8(),
				ce.getOID_2_5_29_17(), SN);
			this.dns = ce.getDNS();
		}
		this.email = ce.getEmail();
	}

	/**
	 * @return boolean is PF
	 */
	public boolean isCertificatePF() {
		return icpBrCertPF != null;
	}

	/**
	 * @return ICPBRCertificatePF ICPBR Certificate PF
	 * @see org.demoiselle.signer.core.extension.ICPBRCertificatePF
	 */
	public ICPBRCertificatePF getICPBRCertificatePF() {
		return icpBrCertPF;
	}

	/**
	 * @return boolean is PJ
	 */
	public boolean isCertificatePJ() {
		return icpBrCertPJ != null;
	}

	/**
	 * @return ICPBRCertificatePJ ICPBR Certificate PJ
	 * @see org.demoiselle.signer.core.extension.ICPBRCertificatePJ
	 */
	public ICPBRCertificatePJ getICPBRCertificatePJ() {
		return icpBrCertPJ;
	}

	/**
	 * @return boolean is Equipment
	 */
	public boolean isCertificateEquipment() {
		return icpBrCertEquipment != null;
	}

	/**
	 * @return ICPBRCertificateEquipment ICPBR Certificate Equipment
	 * @see org.demoiselle.signer.core.extension.ICPBRCertificateEquipment
	 */
	public ICPBRCertificateEquipment getICPBRCertificateEquipment() {
		return icpBrCertEquipment;
	}

	/**
	 * @return String email
	 */
	public String getEmail() {
		return email;
	}

	/**
	 * @return String DNS for  ICPBR Certificate Equipment
	 */
	public String getDns() {
		return dns;
	}

	/**
	 * @param certificate
	 * @return SerialNumber ("2.5.4.5") from Principal Certificate
	 */
	private String getSNfromCertificate(X509Certificate certificate) {
		try {
			X500Name x500name = new JcaX509CertificateHolder(certificate).getSubject();
			RDN[] rdns = x500name.getRDNs();
			for (int i = 0; i < rdns.length; i++) {
				if (rdns[i].getFirst().getType().getId().equals("2.5.4.5"))
					return rdns[i].getFirst().getValue().toString();
			}
			return null;
		} catch (CertificateEncodingException e) {
			return null;
		}
	}

}
