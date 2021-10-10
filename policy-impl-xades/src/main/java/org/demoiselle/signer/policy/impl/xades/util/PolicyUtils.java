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

package org.demoiselle.signer.policy.impl.xades.util;

import org.demoiselle.signer.policy.engine.factory.PolicyFactory;

/**
 * Utility Class for XML Policy treatment
 *
 * @author emerson.saito@serpro.gov.br
 */
public class PolicyUtils {

	/**
	 * return the policy by OID.
	 *
	 * @param oid the OID.
	 * @return the corresponding {@link PolicyFactory.Policies}.
	 */
	public static PolicyFactory.Policies getPolicyByOid(String oid) {

		switch (oid) {

			case "2.16.76.1.7.1.6.2.1":
				return PolicyFactory.Policies.AD_RB_XADES_2_1;
			case "2.16.76.1.7.1.6.2.2":
				return PolicyFactory.Policies.AD_RB_XADES_2_2;
			case "2.16.76.1.7.1.6.2.3":
				return PolicyFactory.Policies.AD_RB_XADES_2_3;
			case "2.16.76.1.7.1.6.2.4":
				return PolicyFactory.Policies.AD_RB_XADES_2_4;

			case "2.16.76.1.7.1.7.2.1":
				return PolicyFactory.Policies.AD_RT_XADES_2_1;
			case "2.16.76.1.7.1.7.2.2":
				return PolicyFactory.Policies.AD_RT_XADES_2_2;
			case "2.16.76.1.7.1.7.2.3":
				return PolicyFactory.Policies.AD_RT_XADES_2_3;
			case "2.16.76.1.7.1.7.2.4":
				return PolicyFactory.Policies.AD_RT_XADES_2_4;

			case "2.16.76.1.7.1.8.2.2":
				return PolicyFactory.Policies.AD_RV_XADES_2_2;
			case "2.16.76.1.7.1.8.2.3":
				return PolicyFactory.Policies.AD_RV_XADES_2_3;
			case "2.16.76.1.7.1.8.2.4":
				return PolicyFactory.Policies.AD_RV_XADES_2_4;

			case "2.16.76.1.7.1.9.2.3":
				return PolicyFactory.Policies.AD_RC_XADES_2_3;
			case "2.16.76.1.7.1.9.2.4":
				return PolicyFactory.Policies.AD_RC_XADES_2_4;

			case "2.16.76.1.7.1.10.2.3":
				return PolicyFactory.Policies.AD_RA_XADES_2_3;
			case "2.16.76.1.7.1.10.2.4":
				return PolicyFactory.Policies.AD_RA_XADES_2_4;

			default:
				return null;
		}
	}
}
