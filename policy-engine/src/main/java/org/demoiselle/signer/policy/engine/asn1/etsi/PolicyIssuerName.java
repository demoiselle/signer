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

package org.demoiselle.signer.policy.engine.asn1.etsi;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;

/**
 * The policyIssuerName field identifies the policy issuer in one or more of the general name forms.
 * <p>
 * PolicyIssuerName ::= GeneralNames
 *
 * @see ASN1Encodable
 * @see ASN1Primitive
 * @see ASN1Sequence
 * @see DEROctetString
 * @see DERPrintableString
 * @see DERSequence
 * @see DERSet
 * @see DERTaggedObject
 * @see DERUTF8String
 * @see DLSequence
 * @see ASN1Object
 */
public class PolicyIssuerName extends ASN1Object {

	private Map<ObjectIdentifier, String> issuerNames;
	private String issuerName;
	private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");

	@Override
	public void parse(ASN1Primitive primitive) {
		if (primitive instanceof DLSequence) {
			DLSequence sequence = (DLSequence) primitive;
			ASN1Encodable asn1Encodable = sequence.getObjectAt(0);
			if (asn1Encodable instanceof DERTaggedObject) {
				DERTaggedObject derTaggedObject = (DERTaggedObject) asn1Encodable;
				ASN1Primitive object = derTaggedObject.getObject();
				if (object instanceof DEROctetString) {
					OctetString octetString = new OctetString();
					octetString.parse(object);
					this.issuerName = octetString.getValueUTF8();
				} else if (object instanceof DERSequence) {
					DERSequence sequence2 = (DERSequence) object;
					for (int i = 0; i < sequence2.size(); i++) {
						ASN1Encodable obj = sequence2.getObjectAt(i);
						if (obj instanceof DERSet) {
							DERSet set = (DERSet) obj;
							ASN1Encodable object2 = set.getObjectAt(0);
							if (object2 instanceof DERSequence) {
								DERSequence sequence3 = (DERSequence) object2;
								ObjectIdentifier objectIdendifier = new ObjectIdentifier();
								objectIdendifier.parse(sequence3.getObjectAt(0).toASN1Primitive());
								String name = null;
								ASN1Encodable object3 = sequence3.getObjectAt(1);
								if (object3 instanceof DERPrintableString) {
									name = ((DERPrintableString) object3).getString();
								} else if (object3 instanceof DERUTF8String) {
									name = ((DERUTF8String) object3).getString();
								} else {
									System.out.println(policyMessagesBundle.getString("error.not.recognized.object", object3.getClass(), object3.toString()));
								}
								if (this.issuerNames == null) {
									this.issuerNames = new HashMap<ObjectIdentifier, String>();
								}
								this.issuerNames.put(objectIdendifier, name);
							}
						}
					}
				}
			}
		}
	}

	public Map<ObjectIdentifier, String> getIssuerNames() {
		return issuerNames;
	}

	public void setIssuerNames(Map<ObjectIdentifier, String> issuerNames) {
		this.issuerNames = issuerNames;
	}

	public String getIssuerName() {
		return issuerName;
	}

	public void setIssuerName(String issuerName) {
		this.issuerName = issuerName;
	}

	@Override
	public String toString() {
		if (this.issuerName != null) {
			return this.issuerName;
		}
		String result = "";
		if (this.issuerNames != null && !this.issuerNames.isEmpty()) {
			for (ObjectIdentifier oid : this.issuerNames.keySet()) {
				result = result + oid.getValue() + "=" + this.issuerNames.get(oid) + ",";
			}
			return result.substring(0, result.length() - 1);
		}
		return null;
	}
}
