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
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

public class GenerateCerts {

	@SuppressWarnings("resource")
	public static void main(String[] args) {

		Authority authority = new Authority();

		try {

			KeyStore keyStore = CertificateHelper.createRootCertificate(authority, "PKCS12");

			new FileOutputStream(new File("/tmp/new_ca.cer"))
					.write(keyStore.getCertificate(authority.alias()).getEncoded());

			keyStore.store(new FileOutputStream("/tmp/new_ca.p12"), "changeit".toCharArray());

			KeyStore keyStore2 = CertificateHelper.createServerCertificate("localhost",
					new SubjectAlternativeNameHolder(), authority, keyStore.getCertificate(authority.alias()),
					(PrivateKey) keyStore.getKey(authority.alias(), "changeit".toCharArray()));

			keyStore2.store(new FileOutputStream("/tmp/new_cert_localhost.p12"), "changeit".toCharArray());

			new FileOutputStream(new File("/tmp/new_cert_localhost.cer"))
					.write(keyStore2.getCertificate(authority.alias()).getEncoded());

		} catch (Throwable e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
