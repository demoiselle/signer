package org.demoiselle.signer.agent.desktop.command.policy;

import org.demoiselle.signer.agent.desktop.web.Request;

public class ListPoliciesRequest extends Request {
	
	public ListPoliciesRequest() {
		super.setCommand("listpolicies");
	}
	
}
