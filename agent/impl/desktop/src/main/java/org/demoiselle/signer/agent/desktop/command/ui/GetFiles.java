package org.demoiselle.signer.agent.desktop.command.ui;

import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.web.Execute;

public class GetFiles extends AbstractCommand<ListGetFilesRequest, ListGetFilesResponse> {

	@Override
	public ListGetFilesResponse doCommand(ListGetFilesRequest request) {
		try {
			
			ListGetFilesResponse response = new ListGetFilesResponse();
			response.setFileName();
			return response;
		} catch (Throwable error) {
			throw new RuntimeException("Erro ao tentar buscar os certificados digitais");
		}
	}

	public static void main(String[] args) {
		System.out.println((new Execute()).executeCommand(new ListGetFilesRequest()));
	}
}
