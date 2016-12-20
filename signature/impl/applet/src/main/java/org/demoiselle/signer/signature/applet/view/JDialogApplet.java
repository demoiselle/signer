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
package org.demoiselle.signer.signature.applet.view;

import org.demoiselle.signer.signature.applet.action.AppletExecute;
import org.demoiselle.signer.signature.applet.config.AppletConfig;
import org.demoiselle.signer.signature.applet.factory.AppletExecuteFactory;
import org.demoiselle.signer.signature.applet.factory.FactoryException;

import java.awt.Component;
import java.awt.Container;
import java.awt.Frame;
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
import javax.swing.WindowConstants;

import netscape.javascript.JSObject;

/**
 * @deprecated  As of release 2.0.0, see org.demoiselle.signer.jnlp project
 */

@Deprecated
public class JDialogApplet extends JApplet {

    private static final long serialVersionUID = 1L;

    public static Frame getParentFrame(Component child) {
        Container c = child.getParent();
        while (c != null) {
            if (c instanceof Frame) {
                return (Frame) c;
            }
            c = c.getParent();
        }
        return null;
    }
    private JKeyStoreDialog keyStoreDialog;

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
        keyStoreDialog = new JKeyStoreDialog();

        this.getContentPane().setLayout(null);
        this.setSize(keyStoreDialog.getDimension());
        this.getRootPane().setDefaultButton(keyStoreDialog.getRunButton());

        keyStoreDialog.addButtonCancelActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cancelButton_actionPerformed();
            }
        });

        keyStoreDialog.addButtonRunActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                runButton_actionPerformed();
            }
        });

        keyStoreDialog.addScrollPaneLineKeyListener(new KeyListener() {

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

        keyStoreDialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        keyStoreDialog.setComponentOrientation(this.getComponentOrientation());
        keyStoreDialog.setLocationRelativeTo(this);

        if (keyStoreDialog.getCertificatesCount() != 0) {
            keyStoreDialog.setVisible(true);
        }

        // Se ocorrer uma falha no carregamento do keystore, efetua a chamada do
        // javascript a ser executado neste caso
        if (!keyStoreDialog.isLoaded()) {
            JSObject window = JSObject.getWindow(this);
            window.call(AppletConfig.PARAM_APPLET_JAVASCRIPT_POSTACTION_FAILURE.getValue(), null);
        }
    }

    private void table_KeyPressed(KeyEvent e) {
        switch (e.getKeyCode()) {
            case KeyEvent.VK_TAB: // se a tecla pressionada for tab
                int rowCount = keyStoreDialog.getTable().getRowCount();
                int selectedRow = keyStoreDialog.getTable().getSelectedRow();

                if (selectedRow == rowCount - 1) {
                    keyStoreDialog.getTable().requestFocus();
                    keyStoreDialog.getTable().changeSelection(0, 0, false, false);
                } else {
                    keyStoreDialog.getTable().requestFocus();
                    keyStoreDialog.getTable().changeSelection(selectedRow + 1, 0, false, false);
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
            KeyStore keystore = keyStoreDialog.getKeyStore();
            String alias = keyStoreDialog.getAlias();

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
        } finally {
            keyStoreDialog.dispose();
        }
    }

    /**
     * Chamado ao clique do botao Cancelar
     */
    private void cancelButton_actionPerformed() {

        KeyStore keystore = keyStoreDialog.getKeyStore();
        String alias = keyStoreDialog.getAlias();

        keyStoreDialog.dispose();
        String className = this.getParameter(AppletConfig.PARAM_APPLET_ACTION_EXECUTE.getKey());
        AppletExecute appletExecute = AppletExecuteFactory.factory(className);
        appletExecute.cancel(keystore, alias, this);
    }

}
