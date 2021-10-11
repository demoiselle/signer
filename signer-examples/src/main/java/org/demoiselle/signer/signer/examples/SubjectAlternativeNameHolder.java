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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;

public class SubjectAlternativeNameHolder {

	private static final Pattern TAGS_PATTERN = Pattern
			.compile("[" + GeneralName.iPAddress + GeneralName.dNSName + "]");

	private final List<ASN1Encodable> sans = new ArrayList<>();

	public void addIpAddress(String ipAddress) {
		sans.add(new GeneralName(GeneralName.iPAddress, ipAddress));
	}

	public void addDomainName(String subjectAlternativeName) {
		sans.add(new GeneralName(GeneralName.dNSName, subjectAlternativeName));
	}

	public void fillInto(X509v3CertificateBuilder certGen) throws CertIOException {
		if (!sans.isEmpty()) {
			ASN1Encodable[] encodables = sans.toArray(new ASN1Encodable[sans.size()]);
			certGen.addExtension(Extension.subjectAlternativeName, false, new DERSequence(encodables));
		}
	}

	public void addAll(Collection<List<?>> subjectAlternativeNames) {
		if (subjectAlternativeNames != null) {
			for (List<?> each : subjectAlternativeNames) {
				sans.add(parseGeneralName(each));
			}
		}
	}

	private ASN1Encodable parseGeneralName(List<?> nameEntry) {
		if (nameEntry != null && nameEntry.size() != 2) {
			throw new IllegalArgumentException(String.valueOf(nameEntry));
		}
		String tag = String.valueOf(nameEntry.get(0));
		Matcher m = TAGS_PATTERN.matcher(tag);
		if (m.matches()) {
			return new GeneralName(Integer.valueOf(tag), String.valueOf(nameEntry.get(1)));
		}
		throw new IllegalArgumentException(String.valueOf(nameEntry));
	}
}
