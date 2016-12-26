package org.demoiselle.signer.agent.desktop.command.ui;

import org.demoiselle.signer.agent.desktop.web.Request;

public class ListGetFilesRequest extends Request {
	
	public ListGetFilesRequest() {
		super.setCommand("getfiles");
	}
}
