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

package org.demoiselle.signer.policy.impl.xades;

/**
 * Class for representing XML ICP-Brasil policies by respective OID.
 *
 * @author emerson.saito@serpro.gov.br
 */
public enum XMLPoliciesOID {

	AD_RB_XADES_2_1("2.16.76.1.7.1.6.2.1", "AD_RB_XADES_2_1"),
	AD_RB_XADES_2_2("2.16.76.1.7.1.6.2.2", "AD_RB_XADES_2_2"),
	AD_RB_XADES_2_3("2.16.76.1.7.1.6.2.3", "AD_RB_XADES_2_3"),
	AD_RB_XADES_2_4("2.16.76.1.7.1.6.2.4", "AD_RB_XADES_2_4"),

	AD_RT_XADES_2_1("2.16.76.1.7.1.7.2.1", "AD_RT_XADES_2_1"),
	AD_RT_XADES_2_2("2.16.76.1.7.1.7.2.2", "AD_RT_XADES_2_2"),
	AD_RT_XADES_2_3("2.16.76.1.7.1.7.2.3", "AD_RT_XADES_2_3"),
	AD_RT_XADES_2_4("2.16.76.1.7.1.7.2.4", "AD_RT_XADES_2_4"),

	AD_RV_XADES_2_2("2.16.76.1.7.1.8.2.2", "AD_RV_XADES_2_2"),
	AD_RV_XADES_2_3("2.16.76.1.7.1.8.2.3", "AD_RV_XADES_2_3"),
	AD_RV_XADES_2_4("2.16.76.1.7.1.8.2.4", "AD_RV_XADES_2_4"),

	AD_RC_XADES_2_3("2.16.76.1.7.1.9.2.3", "AD_RC_XADES_2_3"),
	AD_RC_XADES_2_4("2.16.76.1.7.1.9.2.4", "AD_RC_XADES_2_4"),

	AD_RA_XADES_2_3("2.16.76.1.7.1.10.2.3", "AD_RA_XADES_2_3"),
	AD_RA_XADES_2_4("2.16.76.1.7.1.10.2.4", "AD_RA_XADES_2_4");

	private final String OID;
	private final String policyName;

	XMLPoliciesOID(String parmOID, String parmPolicyName) {
		this.OID = parmOID;
		this.policyName = parmPolicyName;

	}

	public String getOID() {
		return OID;
	}

	public String getPolicyName() {
		return policyName;
	}

	public static String getPolicyNameByOID(String oid) {
		switch (oid) {
		case "2.16.76.1.7.1.6.2.1": {
			return AD_RB_XADES_2_1.getPolicyName();
		}
		case "2.16.76.1.7.1.6.2.2": {
			return AD_RB_XADES_2_2.getPolicyName();
		}
		case "2.16.76.1.7.1.6.2.3": {
			return AD_RB_XADES_2_3.getPolicyName();
		}
		case "2.16.76.1.7.1.6.2.4": {
			return AD_RB_XADES_2_4.getPolicyName();
		}
		case "2.16.76.1.7.1.7.2.1": {
			return AD_RT_XADES_2_1.getPolicyName();
		}
		case "2.16.76.1.7.1.7.2.2": {
			return AD_RT_XADES_2_2.getPolicyName();
		}
		case "2.16.76.1.7.1.7.2.3": {
			return AD_RT_XADES_2_3.getPolicyName();
		}
		case "2.16.76.1.7.1.7.2.4": {
			return AD_RT_XADES_2_4.getPolicyName();
		}
		case "2.16.76.1.7.1.8.2.2": {
			return AD_RV_XADES_2_2.getPolicyName();
		}
		case "2.16.76.1.7.1.8.2.3": {
			return AD_RV_XADES_2_3.getPolicyName();
		}
		case "2.16.76.1.7.1.8.2.4": {
			return AD_RV_XADES_2_4.getPolicyName();
		}
		case "2.16.76.1.7.1.9.2.3": {
			return AD_RC_XADES_2_3.getPolicyName();
		}
		case "2.16.76.1.7.1.9.2.4": {
			return AD_RC_XADES_2_4.getPolicyName();
		}

		case "2.16.76.1.7.1.10.2.3": {
			return AD_RA_XADES_2_3.getPolicyName();
		}
		case "2.16.76.1.7.1.10.2.4": {
			return AD_RA_XADES_2_4.getPolicyName();
		}
		default: {
			return AD_RB_XADES_2_4.getPolicyName();
		}

		}
	}

}
