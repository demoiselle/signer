package org.demoiselle.signer.agent.desktop.command.policy;

import java.util.HashSet;

import org.demoiselle.signer.agent.desktop.web.Response;

public class ListPoliciesResponse extends Response {
	
	private HashSet<String> policies = new HashSet<String>();
	
	public ListPoliciesResponse() {
		super.setCommand("listpolicies");
	}

	public HashSet<String> getPolicies() {
		return policies;
	}

	public void setPolicies(HashSet<String> policies) {
		this.policies = policies;
	}
	
}
