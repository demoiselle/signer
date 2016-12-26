package org.demoiselle.signer.agent.desktop.ui;

import java.io.File;

import javax.swing.JFileChooser;

public class FileManager {
	public static void main(String[] args){
		(new FileManager()).loadChoser();
	}
	
	public static String getFileName(){
		return (new FileManager()).loadChoser();
	}
	
	public String loadChoser(){
		JFileChooser fileChooser = new JFileChooser();
		int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
          File selectedFile = fileChooser.getSelectedFile();
          return selectedFile.getAbsolutePath();
        }
        return null;
	}

}
