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

package org.demoiselle.signer.signer.examples;

import java.io.File;

/**
 * Parameter object holding personal informations given to a SSLEngineSource.
 *
 * XXX consider to inline within the interface SslEngineSource, if MITM is core
 */
public class Authority {

	private final File keyStoreDir;

	private final String alias;

	private final char[] password;

	private final String commonName;

	private final String organization;

	private final String organizationalUnitName;

	private final String certOrganization;

	private final String certOrganizationalUnitName;

	/**
	 * Create a parameter object with example certificate and certificate
	 * authority informations
	 */
	public Authority() {
		keyStoreDir = new File(".");
		alias = "juliancesar"; // proxy id
		password = "changeit".toCharArray();
		organization = "A"; // proxy name
		commonName = organization + ", describe proxy here"; // MITM is bad
																// normally
		organizationalUnitName = "Certificate Authority";
		certOrganization = organization; // proxy name
		certOrganizationalUnitName = organization
				+ ", describe proxy purpose here, since Man-In-The-Middle is bad normally.";
	}

	/**
	 * Create a parameter object with the given certificate and certificate
	 * authority informations
	 */
	public Authority(File keyStoreDir, String alias, char[] password, String commonName, String organization,
			String organizationalUnitName, String certOrganization, String certOrganizationalUnitName) {
		super();
		this.keyStoreDir = keyStoreDir;
		this.alias = alias;
		this.password = password;
		this.commonName = commonName;
		this.organization = organization;
		this.organizationalUnitName = organizationalUnitName;
		this.certOrganization = certOrganization;
		this.certOrganizationalUnitName = certOrganizationalUnitName;
	}

	public File aliasFile(String fileExtension) {
		return new File(keyStoreDir, alias + fileExtension);
	}

	public String alias() {
		return alias;
	}

	public char[] password() {
		return password;
	}

	public String commonName() {
		return commonName;
	}

	public String organization() {
		return organization;
	}

	public String organizationalUnitName() {
		return organizationalUnitName;
	}

	public String certOrganisation() {
		return certOrganization;
	}

	public String certOrganizationalUnitName() {
		return certOrganizationalUnitName;
	}

}
