package org.demoiselle.signer.policy.engine.xml.icpb;

import static org.junit.Assert.*;

import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;

import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.junit.Test;
import org.xml.sax.SAXException;

public class XMLPolicyValidatorTest {

	@Test
	public void testXMLPolicyValidator() throws ParserConfigurationException, SAXException, IOException {
		
		XMLPolicyValidator xMLPolicyValidator = 
				new XMLPolicyValidator(PolicyFactory.getInstance().loadXMLPolicy(PolicyFactory.Policies.AD_RB_XADES_2_4));
		assertTrue(xMLPolicyValidator.validate());
		
	}

}
