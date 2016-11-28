package org.demoiselle.signer.agente.desktop.ui;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.text.Text;
import javafx.scene.control.TextField;

 
public class Controller {
    @FXML private Text actiontarget;
    @FXML private TextField pwdPIN;

    
    @FXML protected void submitButtonAction(ActionEvent event) {
        actiontarget.setText("Sign in button pressed "+pwdPIN.getText());
    }

}
