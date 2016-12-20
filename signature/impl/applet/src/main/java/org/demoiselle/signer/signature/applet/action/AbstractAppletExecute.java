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
package org.demoiselle.signer.signature.applet.action;

import org.demoiselle.signer.signature.applet.certificate.ICPBrasilCertificate;
import org.demoiselle.signer.signature.core.CertificateManager;

import com.sun.java.browser.dom.DOMAccessException;
import com.sun.java.browser.dom.DOMAccessor;
import com.sun.java.browser.dom.DOMAction;
import com.sun.java.browser.dom.DOMService;
import com.sun.java.browser.dom.DOMUnsupportedException;

import java.applet.Applet;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

import netscape.javascript.JSObject;

import org.w3c.dom.Node;
import org.w3c.dom.html.HTMLCollection;
import org.w3c.dom.html.HTMLDocument;
import org.w3c.dom.html.HTMLFormElement;
import org.w3c.dom.html.HTMLInputElement;

/**
 * Implementação padrao do AppletExecute que fornece alguns recursos para
 * manipulacao do certificado e html
 *
 * @author SUPSD/
 *
 */

/**
 * @deprecated  As of release 2.0.0, see org.demoiselle.signer.jnlp project
 */

@Deprecated 
public abstract class AbstractAppletExecute implements AppletExecute {

    /**
     * Modifica um elemento do formulario html a partir da applet
     *
     * @param applet Applet
     * @param formName Nome do formulario html
     * @param fieldName Nome do campo html
     * @param value Valor do campo html
     */
    public static void setFormField(Applet applet, String formName, String fieldName, String value) {
        try {
            JSObject window = JSObject.getWindow(applet);
            JSObject document = (JSObject) window.getMember("document");
            JSObject forms = (JSObject) document.getMember("forms");
            JSObject form = (JSObject) forms.getMember(formName);
            JSObject elements = (JSObject) form.getMember("elements");
            JSObject element = (JSObject) elements.getMember(fieldName);
            element.setMember("value", value);
        } catch (Throwable error) {
            // em alguns casos ocorre incompatibilidade com internet explorer.
            // Utilizando a Common API (jre 1.6 ou superior) é possível
            // ter a compatibilidade desejada
            setFormFieldFromCommonAPI(applet, formName, fieldName, value);
        }
    }

    /**
     * Obtem do formulario html o valor de um campo
     *
     * @param applet Applet
     * @param formName Nome do formulario html
     * @param fieldName Nome do campo html
     * @return Valor do campo
     */
    public static String getFormField(Applet applet, String formName, String fieldName) {
        String result = "";
        try {
            JSObject window = JSObject.getWindow(applet);
            JSObject document = (JSObject) window.getMember("document");
            JSObject forms = (JSObject) document.getMember("forms");
            JSObject form = (JSObject) forms.getMember(formName);
            JSObject elements = (JSObject) form.getMember("elements");
            JSObject element = (JSObject) elements.getMember(fieldName);
            result = element.eval("value").toString();
        } catch (Throwable error) {
            // em alguns casos ocorre incompatibilidade com internet explorer.
            // Utilizando a Common API (jre 1.6 ou superior) é possível
            // ter a compatibilidade desejada
            result = getFormFieldFromCommonAPI(applet, formName, fieldName);
        }
        return result;
    }

    private static void setFormFieldFromCommonAPI(final Applet applet, final String formName, final String fieldName, final String value) {
        String result = null;
        try {
            DOMService service = DOMService.getService(applet);
            service.invokeAndWait(new DOMAction() {
                @Override
                public Object run(DOMAccessor accessor) {
                    HTMLDocument doc = (HTMLDocument) accessor.getDocument(applet);
                    HTMLCollection forms = doc.getForms();
                    HTMLFormElement form = (HTMLFormElement) forms.namedItem(formName);
                    HTMLCollection elements = form.getElements();
                    int length = elements.getLength();
                    for (int i = 0; i < length; i++) {
                        Node node = elements.item(i);
                        if (node instanceof HTMLInputElement) {
                            HTMLInputElement element = (HTMLInputElement) node;
                            if (element.getName().equalsIgnoreCase(fieldName)) {
                                element.setValue(value);
                            }
                        }
                    }
                    return "";
                }
            });
        } catch (DOMUnsupportedException e1) {
            result = e1.getMessage();
        } catch (DOMAccessException e2) {
            result = e2.getMessage();
        }
    }

    private static String getFormFieldFromCommonAPI(final Applet applet, final String formName, final String fieldName) {
        String result = null;
        try {
            DOMService service = DOMService.getService(applet);
            result = (String) service.invokeAndWait(new DOMAction() {
                @Override
                public Object run(DOMAccessor accessor) {
                    HTMLDocument doc = (HTMLDocument) accessor.getDocument(applet);
                    HTMLCollection forms = doc.getForms();
                    HTMLFormElement form = (HTMLFormElement) forms.namedItem(formName);
                    HTMLCollection elements = form.getElements();
                    int length = elements.getLength();
                    for (int i = 0; i < length; i++) {
                        Node node = elements.item(i);
                        if (node instanceof HTMLInputElement) {
                            HTMLInputElement element = (HTMLInputElement) node;
                            if (element.getName().equalsIgnoreCase(fieldName)) {
                                return element.getValue();
                            }
                        }
                    }
                    return "";
                }
            });
        } catch (DOMUnsupportedException e1) {
            result = e1.getMessage();
        } catch (DOMAccessException e2) {
            result = e2.getMessage();
        }
        return result;
    }

    @Override
    public abstract void execute(KeyStore keystore, String alias, Applet applet);

    @Override
    public abstract void cancel(KeyStore keystore, String alias, Applet applet);

    /**
     * Retorn o objeto carregado com as informacoes do certificado ao formato
     * ICPBrasil
     *
     * @param keystore Keystore do dispositivo
     * @param alias
     * @param isValid Indica se o certificado sera validado
     * @return
     * @throws KeyStoreException
     */
    public ICPBrasilCertificate getICPBrasilCertificate(KeyStore keystore, String alias, boolean isValid) throws KeyStoreException {
        if (alias == null || alias.isEmpty()) {
            alias = keystore.aliases().nextElement();
        }
        X509Certificate x509 = (X509Certificate) keystore.getCertificateChain(alias)[0];
        CertificateManager cm = new CertificateManager(x509, isValid);
        ICPBrasilCertificate cert = cm.load(ICPBrasilCertificate.class);
        return cert;
    }
}
