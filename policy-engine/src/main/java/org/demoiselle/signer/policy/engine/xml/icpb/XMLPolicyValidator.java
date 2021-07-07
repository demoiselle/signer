package org.demoiselle.signer.policy.engine.xml.icpb;

import org.demoiselle.signer.policy.engine.exception.PolicyException;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XMLPolicyValidator {

	private LPAXML listOfXMLPolicies;
	private XMLSignaturePolicy xsp;

	private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");
	private static final Logger LOGGER = LoggerFactory.getLogger(XMLPolicyValidator.class);

	
	
	public XMLPolicyValidator(XMLSignaturePolicy xsp) {
		super();
		this.xsp = xsp;
	}



	public boolean validate() {
		boolean valid = true;
		try {
			PolicyFactory factory = PolicyFactory.getInstance();
			listOfXMLPolicies = factory.loadLPAXAdES();

		} catch (Exception ex) {
			throw new PolicyException(ex.getMessage(), ex);
		}
		return valid;
	}

}
