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

package org.demoiselle.signer.core.oid;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.demoiselle.signer.core.util.MessagesBundle;

import sun.security.util.DerValue;
import sun.security.x509.OtherName;

/**
 * Generic Class for treatment of some attributes of certificates of ICP-BRASIL,
 * for: Individual (Pessoa Física) of the Business Entity (Pessoa Jurídica) and Equipment.
 * In accordance with the standards defined in DOC-ICP-04 v2.0 dated 04/18/2006.
 */
@SuppressWarnings("restriction")
public class OIDGeneric {

	private String oid = null;
	private String data = null;
	private static String packageName = "org.demoiselle.signer.core.oid.OID_";
	protected Map<String, String> properties = new HashMap<String, String>();
	private static ASN1InputStream is;
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	protected OIDGeneric() {
	}

	/**
	 * Instance for OIDGeneric.
	 *
	 * @param data Set of bytes with the contents of the certificate.
	 * @return Object GenericOID
	 * @throws IOException exception of input/output
	 * @throws Exception   general exception
	 */
	public static OIDGeneric getInstance(byte[] data) throws IOException, Exception {
		is = new ASN1InputStream(data);
		org.bouncycastle.asn1.ASN1Primitive prim = is.readObject();
		org.bouncycastle.asn1.ASN1Sequence sequence;
		if (prim instanceof org.bouncycastle.asn1.ASN1Sequence) {
			sequence = (org.bouncycastle.asn1.ASN1Sequence) prim;
		} else if (prim instanceof org.bouncycastle.asn1.ASN1TaggedObject) {
			sequence = org.bouncycastle.asn1.ASN1Sequence.getInstance(((org.bouncycastle.asn1.ASN1TaggedObject) prim).getBaseObject());
		} else {
			throw new Exception("Formato de OtherName inválido");
		}
		
		ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) sequence.getObjectAt(0);
		ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence.getObjectAt(1);
		ASN1Encodable innerEncoded = taggedObject.getBaseObject();

		// Em BC 1.80, getBaseObject() pode retornar DLTaggedObject (não DERTaggedObject)
		// ou já retornar o conteúdo diretamente sem wrapper adicional
		ASN1Encodable valueEncoded;
		if (innerEncoded instanceof ASN1TaggedObject) {
			valueEncoded = ((ASN1TaggedObject) innerEncoded).getBaseObject();
		} else {
			valueEncoded = innerEncoded;
		}

		String stringValue = null;
		if (valueEncoded instanceof ASN1OctetString) {
			stringValue = new String(((ASN1OctetString) valueEncoded).getOctets());
		} else if (valueEncoded instanceof ASN1String) {
			stringValue = ((ASN1String) valueEncoded).getString();
		}

		String className = getPackageName() + oid.getId().replaceAll("[.]", "_");
		OIDGeneric oidGenerico;
		try {
			oidGenerico = (OIDGeneric) Class.forName(className).newInstance();
		} catch (InstantiationException e) {
			throw new Exception(coreMessagesBundle.getString("error.class.instance", className), e);
		} catch (IllegalAccessException e) {
			throw new Exception(coreMessagesBundle.getString("error.class.illegal.access", className), e);
		} catch (ClassNotFoundException e) {
			oidGenerico = new OIDGeneric();
		}

		oidGenerico.oid = oid.getId();

		oidGenerico.data = stringValue;

		oidGenerico.initialize();

		return oidGenerico;
	}

	/**
	 * @param der Content of Certificate on sun.security.util.DerValue format
	 * @return OIDGenerico current instance
	 * @throws IOException input/output exception
	 * @throws Exception   general exception
	 */
	public static OIDGeneric getInstance(DerValue der) throws IOException, Exception {
		OtherName on = new OtherName(der);
		String className = getPackageName() + on.getOID().toString().replaceAll("[.]", "_");

		OIDGeneric oidGenerico;
		try {
			oidGenerico = (OIDGeneric) Class.forName(className).newInstance();
		} catch (InstantiationException e) {
			throw new Exception(coreMessagesBundle.getString("error.class.instance", className), e);
		} catch (IllegalAccessException e) {
			throw new Exception(coreMessagesBundle.getString("error.class.illegal.access", className), e);
		} catch (ClassNotFoundException e) {
			oidGenerico = new OIDGeneric();
		}

		oidGenerico.oid = on.getOID().toString();
		oidGenerico.data = new String(on.getNameValue()).substring(6);
		oidGenerico.initialize();

		return oidGenerico;
	}

	protected void initialize() {
		// Inicializa as propriedades do conteudo DATA
	}

	/**
	 * @param fields Fields of a certificate
	 */
	protected void initialize(Object[] fields) {

		int tmp = 0;

		for (int i = 0; i < fields.length; i += 2) {
			String key = (String) fields[i];
			int size = ((Integer) fields[i + 1]);
			properties.put(key, data.substring(tmp, Math.min(tmp + size, data.length())));
			tmp += size;
		}
	}

	/**
	 * @return set of OID on String format
	 */
	public String getOid() {
		return oid;
	}

	/**
	 * @return content on String format
	 */
	public String getData() {
		return data;
	}

	public static String getPackageName() {
		return packageName;
	}

}
