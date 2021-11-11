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
 * ICP-BRASIL's definitions of Key Usage.
 */
public class ICPBRKeyUsage {

	private static final String[] KEY_USAGE = {
		"digitalSignature",
		"nonRepudiation",
		"keyEncipherment",
		"dataEncipherment",
		"keyAgreement",
		"keyCertSign",
		"cRLSign",
		"encipherOnly",
		"decipherOnly"
	};

	private final boolean[] keyUsage;

	/**
	 * @param cert X509Certificate
	 */
	public ICPBRKeyUsage(X509Certificate cert) {
		this.keyUsage = cert.getKeyUsage();
	}

	/**
	 * Fake.
	 *
	 * @return Fake boolean.
	 */
	public boolean isDigitalSignature() {
		return keyUsage[0];
	}

	/**
	 * Fake.
	 *
	 * @return Fake boolean.
	 */
	public boolean isNonRepudiation() {
		return keyUsage[1];
	}

	/**
	 * Fake.
	 *
	 * @return Fake boolean.
	 */
	public boolean isKeyEncipherment() {
		return keyUsage[2];
	}

	/**
	 * Fake.
	 *
	 * @return Fake boolean.
	 */
	public boolean isDataEncipherment() {
		return keyUsage[3];
	}

	/**
	 * Fake.
	 *
	 * @return Fake boolean.
	 */
	public boolean isKeyAgreement() {
		return keyUsage[4];
	}

	/**
	 * Checks.
	 *
	 * @return cert sign.
	 */
	public boolean isKeyCertSign() {
		return keyUsage[5];
	}

	/**
	 * Get is CRL sign.
	 *
	 * @return is CRL sign.
	 */
	public boolean isCRLSign() {
		return keyUsage[6];
	}

	public boolean isEncipherOnly() {
		return keyUsage[7];
	}

	/**
	 * Get if is only cipher.
	 *
	 * @return is only cipher.
	 */
	public boolean isDecipherOnly() {
		return keyUsage[8];
	}

	@Override
	public String toString() {
		String ret = "";
		if (keyUsage != null) {
			for (int i = 0; i < keyUsage.length; i++) {
				if (keyUsage[i]) {
					if (ret.length() > 0) {
						ret += ", ";
					}
					ret += KEY_USAGE[i];
				}
			}
		}
		return ret;
	}
}
