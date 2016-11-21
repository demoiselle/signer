/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
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
package org.demoiselle.signer.signature.applet.view;

import org.demoiselle.signer.signature.applet.action.AppletExecute;
import org.demoiselle.signer.signature.applet.config.AppletConfig;
import org.demoiselle.signer.signature.applet.factory.AppletExecuteFactory;
import org.demoiselle.signer.signature.applet.factory.FactoryException;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.security.KeyStore;

import javax.swing.JApplet;
import javax.swing.JOptionPane;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;
import javax.swing.UnsupportedLookAndFeelException;

import netscape.javascript.JSObject;

public class JPanelApplet extends JApplet {

    private static final long serialVersionUID = -8768328158163719122L;
    private JKeyStorePanel keyStorePanel;

    /**
     * Inicializacao da Applet
     */
    @Override
    public void init() {

        for (LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
            if (AppletConfig.LOOK_AND_FEEL.getValue().equals(info.getName())) {
                try {
                    UIManager.setLookAndFeel(info.getClassName());
                } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException e) {
                    e.printStackTrace();
                }
                break;
            }
        }

        AppletConfig.setApplet(this);
        keyStorePanel = new JKeyStorePanel();
        this.getContentPane().setLayout(null);
        this.setSize(keyStorePanel.getDimension());
        this.getRootPane().setDefaultButton(keyStorePanel.getRunButton());

        keyStorePanel.addButtonCancelActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cancelButton_actionPerformed();
            }
        });

        keyStorePanel.addButtonRunActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                runButton_actionPerformed();
            }
        });

        keyStorePanel.addScrollPaneLineKeyListener(new KeyListener() {

            @Override
            public void keyTyped(KeyEvent e) {

            }

            @Override
            public void keyReleased(KeyEvent e) {

            }

            @Override
            public void keyPressed(KeyEvent e) {
                table_KeyPressed(e);
            }
        });

        this.getContentPane().add(keyStorePanel);
        requestFocusInWindow();

        // Se ocorrer uma falha no carregamento do keystore, efetua a chamada do
        // javascript a ser executado neste caso
        if (!keyStorePanel.isLoaded()) {
            JSObject window = JSObject.getWindow(this);
            window.call(AppletConfig.PARAM_APPLET_JAVASCRIPT_POSTACTION_FAILURE.getValue(), null);
        }
    }

    private void table_KeyPressed(KeyEvent e) {
        switch (e.getKeyCode()) {
            case KeyEvent.VK_TAB: // se a tecla pressionada for tab
                int rowCount = keyStorePanel.getTable().getRowCount();
                int selectedRow = keyStorePanel.getTable().getSelectedRow();

                if (selectedRow == rowCount - 1) {
                    keyStorePanel.getTable().requestFocus();
                    keyStorePanel.getTable().changeSelection(0, 0, false, false);
                } else {
                    keyStorePanel.getTable().requestFocus();
                    keyStorePanel.getTable().changeSelection(selectedRow + 1, 0, false, false);
                }
                break;

            case KeyEvent.VK_SPACE: // Se a tecla pressionada for o espaco
                runButton_actionPerformed();
                break;
        }
    }

    /**
     * Chamado ao clique do botao Ok
     */
    private void runButton_actionPerformed() {

        try {
            KeyStore keystore = keyStorePanel.getKeyStore();
            String alias = keyStorePanel.getAlias();

            if (keystore != null) {
                String className = this.getParameter(AppletConfig.PARAM_APPLET_ACTION_EXECUTE.getKey());
                AppletExecute appletExecute = AppletExecuteFactory.factory(className);
                appletExecute.execute(keystore, alias, this);
            }
        } catch (FactoryException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, e.getMessage(), AppletConfig.LABEL_DIALOG_OPTION_PANE_TITLE.getValue(), JOptionPane.ERROR_MESSAGE);
        } catch (Throwable e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, AppletConfig.MESSAGE_ERROR_UNEXPECTED.getValue() + " - " + e.getMessage(), AppletConfig.LABEL_DIALOG_OPTION_PANE_TITLE.getValue(), JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Chamado ao clique do botao Cancelar
     */
    private void cancelButton_actionPerformed() {
        this.setVisible(false);
        KeyStore keystore = keyStorePanel.getKeyStore();
        String alias = keyStorePanel.getAlias();

        keyStorePanel = null;
        String className = this.getParameter(AppletConfig.PARAM_APPLET_ACTION_EXECUTE.getKey());
        AppletExecute appletExecute = AppletExecuteFactory.factory(className);
        appletExecute.cancel(keystore, alias, this);
    }

}
