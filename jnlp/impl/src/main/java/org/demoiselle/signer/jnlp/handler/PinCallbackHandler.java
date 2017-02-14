/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 * 
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 * 
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 * 
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 * 
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package org.demoiselle.signer.jnlp.handler;

import java.awt.GridLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.concurrent.CancellationException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import org.demoiselle.signer.signature.core.util.MessagesBundle;

/**
 * CallBackHandler implementation to show window to ask user for his certificate's PIN
*/
public class PinCallbackHandler implements CallbackHandler {

	private static MessagesBundle messagesBundle = new MessagesBundle();
	
	/**
	 *
	 * @param passwordCallback
	 * @throws UnsupportedCallbackException 
	 */
	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                handlePasswordCallback((PasswordCallback) callback);
            } else {
                throw new UnsupportedCallbackException(callback, messagesBundle.getString("error.callback.notsupported", callback.getClass().getName()));
            }
        }
    }

    /**
     * 
     * @param passwordCallback
     * @throws UnsupportedCallbackException
     */
    private void handlePasswordCallback(PasswordCallback passwordCallback) throws UnsupportedCallbackException {
        // dialog
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(2, 1));

        // label
        panel.add(new JLabel(passwordCallback.getPrompt()));

        // password input
        final JTextField txtPwd = new JPasswordField(20);
        panel.add(txtPwd);
        final JOptionPane pane = new JOptionPane(panel, JOptionPane.QUESTION_MESSAGE, JOptionPane.OK_CANCEL_OPTION);
        JDialog dialog = pane.createDialog(null, messagesBundle.getString("info.pin.required"));

        // set focus to password field
        dialog.addWindowListener(new WindowAdapter() {
            @Override
            public void windowOpened(WindowEvent e) {
                txtPwd.requestFocusInWindow();
            }
        });

        // show dialog
        dialog.setVisible(true);
        dialog.dispose();
        int retVal = pane.getValue() != null ? ((Integer) pane.getValue()).intValue() : JOptionPane.CANCEL_OPTION;

        switch (retVal) {
            case JOptionPane.OK_OPTION:
                // return password
                passwordCallback.setPassword(txtPwd.getText().toCharArray());
                break;
            case JOptionPane.CANCEL_OPTION:
                // return password
            	System.exit(0);
            default:
                // canceled by user
                throw new CancellationException(messagesBundle.getString("info.canceled.byuser"));
        }
    }
}
