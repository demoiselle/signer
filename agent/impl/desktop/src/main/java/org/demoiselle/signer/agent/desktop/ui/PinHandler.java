package org.demoiselle.signer.agent.desktop.ui;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.KeyStroke;

public class PinHandler extends JDialog implements CallbackHandler {
	
	private static final long serialVersionUID = 1L;
	private String pwd;
	
	public static void main(String[] args){
		(new PinHandler()).init();
	}
	
	public void init(){
		initUI();
		setVisible(true);
	}
	
	public PinHandler(){
	}
	
	private void initUI() {
		
        setTitle("Pin");
        setSize(500, 250);
        setLocationRelativeTo(null);
		
		setLayout(null);
		setResizable(false);
		final PinHandler me = this;
		
		
		JPanel pane = (JPanel) getContentPane();
		final JPasswordField text = new JPasswordField();
		JLabel lblPin = new JLabel("Informe o Pin:");
        JButton btnValidate = new JButton("Validar");
        JButton btnCancel = new JButton("Cancelar");
        
        pane.setBackground(new Color(0xffffff));
        
        BufferedImage img = null;
		try {
			InputStream path = this.getClass().getClassLoader().getResourceAsStream("META-INF/ui/logoDemoiselle.png"); 
			img = ImageIO.read(path);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
        ImageIcon icon = new ImageIcon(img);
        JLabel lblImg = new JLabel(icon);
        
        btnValidate.setFocusPainted(false);
        btnValidate.setContentAreaFilled(false);
        
        btnCancel.setFocusPainted(false);
        btnCancel.setContentAreaFilled(false);
        
        pane.add(lblImg);
        pane.add(btnValidate);
        pane.add(btnCancel);
        pane.add(lblPin);
        pane.add(text);
        
        lblImg.setBounds(0, 00, 500, 120);
        lblPin.setBounds(20, 150, 100, 15);
        text.setBounds(120, 150, getWidth()-(50+lblPin.getWidth()), 20);
        btnCancel.setBounds((int)(text.getBounds().getMaxX() - 210), 200, 100, 30);
        btnValidate.setBounds((int)(text.getBounds().getMaxX() - 100), 200, 100, 30);
        
   
        btnCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				me.dispose();
				
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
				pwd = new String(text.getPassword());
				me.dispose();
			}
		});
        
        this.setModal(true);
        
    }
	
	public String getPwd(){
		return pwd;
	}

	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
            	initUI();
            	setVisible(true);
            	((PasswordCallback) callback).setPassword(pwd.toCharArray());
            } else {
                throw new UnsupportedCallbackException(callback, "Callback not supported " + callback.getClass().getName());
            }
        }
	}
	
	

}
