package org.demoiselle.signer.agent.desktop.command.policy;

import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.web.Execute;
import org.demoiselle.signer.signature.policy.engine.factory.PolicyFactory.Policies;


public class ListPolicies extends AbstractCommand<ListPoliciesRequest, ListPoliciesResponse> {
	
	@Override
	public ListPoliciesResponse doCommand(ListPoliciesRequest request) {
		ListPoliciesResponse response = new ListPoliciesResponse();
		for (Policies policy : Policies.values())
			response.getPolicies().add(policy.name());
		return response;
	}

	public static void main(String[] args) {
		System.out.println((new Execute()).executeCommand(new ListPoliciesRequest()));
	}


}
