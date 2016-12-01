package org.demoiselle.signer.agent.desktop.ui;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
 
public class InsertPin extends Application {
   String pwd;
	
	public InsertPin(String pwd){
		this.pwd = pwd;
	}
    
	public InsertPin(){
		
	}
	
	public String getPin(){
		return this.pwd;
	}
	
    @Override
    public void start(Stage stage) {
        try{
            Parent root = FXMLLoader.load(getClass().getResource("/META-INF/ui/InsertPin.fxml"));
            stage.resizableProperty().setValue(Boolean.FALSE);
            stage.setScene(new Scene(root));
            stage.show();
        }catch(Exception e){
            e.printStackTrace();
        }
        stage.show();
    }
}

