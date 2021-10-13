/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
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

package org.demoiselle.signer.chain.icp.brasil.provider.impl;

import org.demoiselle.signer.chain.icp.brasil.provider.ChainICPBrasilConfig;

/**
 * Get/Download the ICP-BRASIL's Trusted Certificate Authority Chain
 * (<a href="http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip">
 *     ACcompactado.zip</a>) from ITI.
 */
public class ICPBrasilOnLineITIProviderCA extends ICPBrasilOnLineSerproProviderCA {

	private static String STRING_URL_ZIP = ChainICPBrasilConfig.getInstance().getUrl_iti_ac_list();
	private static String STRING_URL_HASH = ChainICPBrasilConfig.getInstance().getUrl_iti_ac_list_sha512();

	/**
	 * Get the address (URL) of a compressed file (zip) with certificates
	 * from ICP-Brasil chain of Certificate Authority.
	 *
	 * @return the address where is located a compacted file that
	 * contains the chain of ICP-BRASIL's trusted Certificate Authority.
	 */
	@Override
	public String getURLZIP() {
		return ICPBrasilOnLineITIProviderCA.STRING_URL_ZIP;
	}

	/**
	 *  Get the address where is located a file that contains the hash code (SHA512)
	 *  which corresponds to the file downloaded with {@link #getURLZIP()}.
	 *
	 * @return address (URL) of hash code (SHA512) of file available at
	 * {@link #getURLZIP()}.
	 */
	public String getURLHash() {
		return ICPBrasilOnLineITIProviderCA.STRING_URL_HASH;
	}

	/**
	 * This provider Name.
	 *
	 * @return the provider name.
	 */
	@Override
	public String getName() {
		return chainMessagesBundle.getString("info.provider.name.iti", getURLZIP());
	}
}
