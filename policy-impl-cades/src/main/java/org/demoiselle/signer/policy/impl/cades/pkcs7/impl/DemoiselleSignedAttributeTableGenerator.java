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

package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSAttributeTableGenerator;

public class DemoiselleSignedAttributeTableGenerator
	implements CMSAttributeTableGenerator {
	private final Hashtable table;

	/**
	 * Initialise to use all defaults
	 */
	public DemoiselleSignedAttributeTableGenerator() {
		table = new Hashtable();
	}

	/**
	 * Initialise with some extra attributes or overrides.
	 *
	 * @param attributeTable initial attribute table to use.
	 */
	public DemoiselleSignedAttributeTableGenerator(
		AttributeTable attributeTable) {
		if (attributeTable != null) {
			table = attributeTable.toHashtable();
		} else {
			table = new Hashtable();
		}
	}

	/**
	 * Create a standard attribute table from the passed in parameters - this will
	 * normally include contentType, signingTime, and messageDigest. If the constructor
	 * using an AttributeTable was used, entries in it for contentType, signingTime, and
	 * messageDigest will override the generated ones.
	 *
	 * @param parameters source parameters for table generation.
	 * @return a filled in Hashtable of attributes.
	 */
	protected Hashtable createStandardAttributeTable(
		Map parameters) {
		Hashtable std = copyHashTable(table);

		if (!std.containsKey(CMSAttributes.contentType)) {
			ASN1ObjectIdentifier contentType = ASN1ObjectIdentifier.getInstance(
				parameters.get(CMSAttributeTableGenerator.CONTENT_TYPE));

			// contentType will be null if we're trying to generate a counter signature.
			if (contentType != null) {
				Attribute attr = new Attribute(CMSAttributes.contentType,
					new DERSet(contentType));
				std.put(attr.getAttrType(), attr);
			}
		}

		if (!std.containsKey(CMSAttributes.messageDigest)) {
			byte[] messageDigest = (byte[]) parameters.get(
				CMSAttributeTableGenerator.DIGEST);
			Attribute attr = new Attribute(CMSAttributes.messageDigest,
				new DERSet(new DEROctetString(messageDigest)));
			std.put(attr.getAttrType(), attr);
		}

		return std;
	}

	/**
	 * @param parameters source parameters
	 * @return the populated attribute table
	 */
	public AttributeTable getAttributes(Map parameters) {
		return new AttributeTable(createStandardAttributeTable(parameters));
	}

	private static Hashtable copyHashTable(Hashtable paramsMap) {
		Hashtable newTable = new Hashtable();

		Enumeration keys = paramsMap.keys();
		while (keys.hasMoreElements()) {
			Object key = keys.nextElement();
			newTable.put(key, paramsMap.get(key));
		}

		return newTable;
	}
}
