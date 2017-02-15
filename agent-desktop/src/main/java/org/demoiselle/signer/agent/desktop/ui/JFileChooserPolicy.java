package org.demoiselle.signer.agent.desktop.ui;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

public class JFileChooserPolicy extends JFileChooser{

	private static final long serialVersionUID = 1L;
	String policy;
	JComboBox cmbPolicy;
	public JFileChooserPolicy(HashSet<String> policies){
		
		List<String> validPolicies = new ArrayList<String>();
		validPolicies.add("--Selecione--");
		
		for (String policy : policies) {
			if(policy.startsWith("AD_RB_CA"))
				validPolicies.add(policy);
		}
		
		String strPolicies [] = (String[])validPolicies.toArray(new String[validPolicies.size()]);
		cmbPolicy = new JComboBox ();
		cmbPolicy.setModel(new DefaultComboBoxModel(strPolicies));

        JPanel pMain = (JPanel)this.getComponent(3);
        JPanel pData = (JPanel) pMain.getComponent(2);

        JLabel c1= (JLabel)pData.getComponent(0);
        c1.setText("Potitica");
        pData.removeAll();
        
        pData.add(c1);
        pData.add(cmbPolicy);
        
	}
	
	
	public String getPolicy(){
		return (String)cmbPolicy.getSelectedItem();
	}
	
	@Override
	public void approveSelection(){
		if(cmbPolicy.getSelectedIndex() < 1)
			JOptionPane.showMessageDialog(null, "Selecione a politica", "Error", JOptionPane.ERROR_MESSAGE);
		else
			super.approveSelection();
			
	}
	
	
}
