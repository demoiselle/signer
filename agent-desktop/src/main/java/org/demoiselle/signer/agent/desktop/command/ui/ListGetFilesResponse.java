package org.demoiselle.signer.agent.desktop.command.ui;

import org.demoiselle.signer.agent.desktop.ui.FileManager;
import org.demoiselle.signer.agent.desktop.web.Response;

public class ListGetFilesResponse extends Response {
	
	private String fileName;
	
	public ListGetFilesResponse() {
		super.setCommand("getfiles");
	}

	public String getFileName(){
		return fileName;
	}
	
	public void setFileName() {
		fileName = FileManager.getFileName();
	}	
}
