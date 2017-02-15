package org.demoiselle.signer.agent.desktop.ui;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;

import org.demoiselle.signer.agent.desktop.command.cert.Certificate;
import org.demoiselle.signer.agent.desktop.command.cert.ListCertsResponse;


public class ListCertificateData extends JDialog{

	private class CertificateData{
		public JRadioButton sentBy;
		public JLabel provider;
		public String alias;
		
		public CertificateData(String sentBy, String provider, String alias){
			this.sentBy = new JRadioButton("<html><span style='font-size:8px;color:#23527c'>"+sentBy+"</span></html>");
			this.provider = new JLabel("<html><span style='font-size:8px;color:#23527c'>"+provider+"</span></html>");
			this.alias = alias;
			this.sentBy.setBackground(new Color(0xffffff));
			this.provider.setBackground(new Color(0xffffff));
	       
		}
	}
	
	private String alias;
	private String provider;
	private static final long serialVersionUID = 1L;
	List<CertificateData> certs;
	
	public static void main(String[] args){
		//ListCertsResponse ls = new ListCertsResponse();
		//ls.getCertificates().add(new Certificate());
		//ListCertsResponse lr = new ListCertificateData(null));
		(new ListCertificateData(null)).init();
		
		
		/*
		 * certs = new ArrayList<ListCertificateData.CertificateData>();
        
        certs.add(new CertificateData("CN=FABIANO SARDENBERG KUSS II, OU=Autoridade Certificadora SERPROACF, OU=ARSERPRO, OU=Pessoa Fisica A3, O=ICP-Brasil, C=BR", 
        		"SunPKCS11-Provedor	", "(1218806) FABIANO SARDENBERG KUSS"));
        certs.add(new CertificateData("CN=FABIANO SARDENBERG KUSS, OU=Autoridade Certificadora SERPROACF, OU=ARSERPRO, OU=Pessoa Fisica A3, O=ICP-Brasil, C=BR", 
        		"SunPKCS11-Provedor	", "(1218806) FABIANO SARDENBERG KUSS I"));

		 * 
		 */
	}
	
	public void init(){
		initUI();
		setVisible(true);
	}
	
	public ListCertificateData(ListCertsResponse certificates){
		certs = new ArrayList<ListCertificateData.CertificateData>();
		for (Certificate c : certificates.getCertificates()) {
			certs.add(new CertificateData(c.getSubject(), c.getProvider(), c.getAlias()));
		}
			
	}
	
	private void initUI() {
	
		
        setTitle("Pin");
        setSize(600, 250);
        setLocationRelativeTo(null);
		
		setLayout(null);
		setResizable(false);
		final ListCertificateData me = this;
		
		
		JPanel pane = (JPanel) getContentPane();
		JLabel title = new JLabel("<html><span style='font-size:15px; color:#23527c'>Selecione um dos Certificados</span></html>");
		
		
		JLabel sentBy = new JLabel("<html><span style='font-size:10px; color:#23527c'>Emitido Para</span></html>");
		JLabel providers = new JLabel("<html><span style='font-size:10px; color:#23527c'>Provedor</span></html>");
				
        JButton btnValidate = new JButton("Selecionar");
        JButton btnCancel = new JButton("Cancelar");
        
        pane.setBackground(new Color(0xffffff));
        
        
        btnValidate.setFocusPainted(false);
        btnValidate.setContentAreaFilled(false);
        
        btnCancel.setFocusPainted(false);
        btnCancel.setContentAreaFilled(false);
        
        
        ButtonGroup bG = new ButtonGroup();
        
                
        
        int ypos = 70;
        for(int i = 0; i < certs.size(); i++){
	        bG.add(certs.get(i).sentBy);
	        bG.add(certs.get(i).sentBy);
	        
	        certs.get(i).sentBy.setBounds(15, ypos, 450, 30);
	        certs.get(i).provider.setBounds(470, ypos, 450, 30);
	        
	        pane.add(certs.get(i).sentBy);
	        pane.add(certs.get(i).provider);
	        
	        JSeparator js = new JSeparator(SwingConstants.HORIZONTAL);
	        pane.add(js);
	        js.setBounds(10, ypos -5, 580, 4);
	        
	        ypos += 35;
        
        }
        
        JSeparator js = new JSeparator(SwingConstants.HORIZONTAL);
        pane.add(js);
        js.setBounds(10, ypos -5, 580, 4);
        
        
        
        pane.add(sentBy);
        pane.add(providers);
        sentBy.setBounds(12, 40, 500, 25);
        providers.setBounds(470, 40, 100, 25);
        
        pane.add(title);
        
        pane.add(btnValidate);
        pane.add(btnCancel);
        
        title.setBounds(12, 10, 300, 25);
        
        btnCancel.setBounds(this.getWidth()-225, 200, 100, 30);
        btnValidate.setBounds(this.getWidth()- 120, 200, 100, 30);
        
   
        btnCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				me.dispose();
				
			}
		});
        
        btnValidate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				for(int i=0; i < certs.size(); i++){
					if(certs.get(i).sentBy.isSelected()){
						alias = certs.get(i).alias;
					}
				}
				
				
			}
		});
        
        getRootPane().setDefaultButton(btnValidate);
        
        
        final AbstractAction escapeAction = new AbstractAction() {
            private static final long serialVersionUID = 1L;

			public void actionPerformed(ActionEvent e) {
				dispose();
			}
        };

        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "ESCAPE_KEY");
        getRootPane().getActionMap().put("ESCAPE_KEY", escapeAction);
        
        
        
        btnValidate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				me.dispose();
			}
		});
        
        this.setModal(true);
        
    }
	
	public String getAlias(){
		return alias;
	}
	
	public String getProvider(){
		return provider;
	}

	

}
