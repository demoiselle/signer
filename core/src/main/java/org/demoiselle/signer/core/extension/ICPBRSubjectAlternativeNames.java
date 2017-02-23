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

import java.security.cert.X509Certificate;

/**
 * 
 * ICP-BRASIL's definitions of Subject Alternative Names 
 *
 */
public class ICPBRSubjectAlternativeNames {

	private String email = null;
	private ICPBRCertificatePF icpBrCertPF = null;
	private ICPBRCertificatePJ icpBrCertPJ = null;
	private ICPBRCertificateEquipment icpBrCertEquipment = null;

	/**
	 * 
	 * @param certificate
	 *            -> X509Certificate
	 * @see java.security.cert.X509Certificate
	 */
	public ICPBRSubjectAlternativeNames(X509Certificate certificate) {
		CertificateExtra ce = new CertificateExtra(certificate);
		if (ce.isCertificatePF()) {
			icpBrCertPF = new ICPBRCertificatePF(ce.getOID_2_16_76_1_3_1(), ce.getOID_2_16_76_1_3_5(), ce.getOID_2_16_76_1_3_6());
		} else if (ce.isCertificatePJ()) {
			icpBrCertPJ = new ICPBRCertificatePJ(ce.getOID_2_16_76_1_3_2(), ce.getOID_2_16_76_1_3_3(), ce.getOID_2_16_76_1_3_4(), ce.getOID_2_16_76_1_3_7());
		} else if (ce.isCertificateEquipment()) {
			icpBrCertEquipment = new ICPBRCertificateEquipment(ce.getOID_2_16_76_1_3_2(), ce.getOID_2_16_76_1_3_3(), ce.getOID_2_16_76_1_3_4(), ce.getOID_2_16_76_1_3_8());
		}
		this.email = ce.getEmail();
	}

	/**
	 * 
	 * @return boolean
	 */
	public boolean isCertificatePF() {
		return icpBrCertPF != null;
	}

	/**
	 * 
	 * @return Object ICPBRCertificatePF
	 * @see org.demoiselle.signer.extension.serpro.security.certificate.extension.ICPBRCertificatePF
	 */
	public ICPBRCertificatePF getICPBRCertificatePF() {
		return icpBrCertPF;
	}

	/**
	 * 
	 * @return boolean
	 */
	public boolean isCertificatePJ() {
		return icpBrCertPJ != null;
	}

	/**
	 * 
	 * @return Object ICPBRCertificatePJ
	 * @see org.demoiselle.signer.extension.serpro.security.certificate.extension.ICPBRCertificatePJ
	 */
	public ICPBRCertificatePJ getICPBRCertificatePJ() {
		return icpBrCertPJ;
	}

	/**
	 * 
	 * @return boolean
	 */
	public boolean isCertificateEquipment() {
		return icpBrCertEquipment != null;
	}

	/**
	 * 
	 * @return Object ICPBRCertificateEquipment
	 * @see org.demoiselle.signer.extension.serpro.security.certificate.extension.ICPBRCertificateEquipment
	 */
	public ICPBRCertificateEquipment getICPBRCertificateEquipment() {
		return icpBrCertEquipment;
	}

	/**
	 * 
	 * @return String
	 */
	public String getEmail() {
		return email;
	}

}
