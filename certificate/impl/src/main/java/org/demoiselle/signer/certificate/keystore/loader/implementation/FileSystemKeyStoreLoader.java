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
package org.demoiselle.signer.certificate.keystore.loader.implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

import javax.security.auth.callback.CallbackHandler;

import org.demoiselle.signer.certificate.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.certificate.keystore.loader.KeyStoreLoaderException;

/**
 * Implementação do carregamento de KeyStore baseado no padrão PKCS12 ou JKS
 *
 */
public class FileSystemKeyStoreLoader implements KeyStoreLoader {

    private static final String FILE_TYPE_PKCS12 = "PKCS12";
    private static final String FILE_TYPE_JKS = "JKS";
    private static final String FILE_LOAD_ERROR = "Error on load a keystore from file";
    private static final String FILE_NOT_VALID = "File invalid or not exist";

    private File fileKeyStore = null;

    /**
     * Construtor da classe Verifique se o parametro informado existe e se é
     * arquivo.
     *
     * @param file File que representa um KeyStore PKCS12 ou JKS
     */
    public FileSystemKeyStoreLoader(File file) {

        if (file == null || !file.exists() || !file.isFile()) {
            throw new KeyStoreLoaderException(FILE_NOT_VALID);
        }

        this.setFileKeyStore(file);

    }

    public File getFileKeyStore() {
        return fileKeyStore;
    }

    public void setFileKeyStore(File fileKeyStore) {
        this.fileKeyStore = fileKeyStore;
    }

    /**
     * Tenta carregar o KeyStore primeiro no padrao PKCS12. Caso nao consiga,
     * armazena a exception recebida e tenta entao carregar um KeyStore no
     * padrao JKS. Nao conseguindo nas duas tentativas, levanta uma exception,
     * por isso este método nunca retornará
     *
     */
    public KeyStore getKeyStore(String pinNumber) {

        System.out.println("FileSystemKeyStoreLoader.getKeyStore()");

        KeyStore result = null;
        try {
            result = this.getKeyStoreWithType(pinNumber, FILE_TYPE_PKCS12);
        } catch (Throwable throwable) {
            try {
                result = this.getKeyStoreWithType(pinNumber, FILE_TYPE_JKS);
            } catch (Throwable error) {
                throw new KeyStoreLoaderException("Error on load a KeyStore from file. KeyStore unknow format", throwable);
            }
        }

        return result;
    }

    /**
     * Nao implementado, utilizar getKeyStore(pinNumer)
     *
     * @return
     */
    @Override
    public KeyStore getKeyStore() {
        System.out.println("Nao implementado");
        return null;
    }

    private KeyStore getKeyStoreWithType(String pinNumber, String keyStoreType) {
        KeyStore result = null;
        try {
            result = KeyStore.getInstance(keyStoreType);
            char[] pwd = pinNumber == null ? null : pinNumber.toCharArray();
            InputStream is = new FileInputStream(this.fileKeyStore);
            result.load(is, pwd);
        } catch (Throwable error) {
            throw new KeyStoreLoaderException(FILE_LOAD_ERROR, error);
        }
        return result;
    }

    @Override
    public void setCallbackHandler(CallbackHandler callback) {

    }

}
