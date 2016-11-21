package org.demoiselle.signer.signature.policy.engine.asn1.icpb;

import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;


public class PoliciesURI extends ASN1Object {
	
	enum TAG {
		textualPolicyURI(0), asn1PolicyURI(1), xmlPolicyURI(2);
		int value;
		private TAG(int value) { this.value = value; }
		public static TAG getTag(int value) {
			for (TAG tag : TAG.values()) if (tag.value == value) {
                            return tag;
                        } return null;
		}
	}
	
	private String textualPolicyURI;
	private String asn1PolicyURI;
	private String xmlPolicyURI;

}
