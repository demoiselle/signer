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
package org.demoiselle.signer.signature.core.keystore.loader.factory;

import org.demoiselle.signer.signature.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.signature.core.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.signature.core.keystore.loader.configuration.Configuration;
import org.demoiselle.signer.signature.core.keystore.loader.implementation.DriverKeyStoreLoader;
import org.demoiselle.signer.signature.core.keystore.loader.implementation.FileSystemKeyStoreLoader;
import org.demoiselle.signer.signature.core.keystore.loader.implementation.MSKeyStoreLoader;

import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyStoreLoaderFactory {

    private static final Logger logger = LoggerFactory.getLogger(KeyStoreLoaderFactory.class);

    /**
     * Método responsável por fabricar uma instância de KeyStoreLoader baseado
     * em PKCS#11.<br>
     * Normalmente este método fabrica carregadores baseados nas configurações
     * do ambiente.<br>
     * Pode-se fabricar instancias voltadas para ambiente windows ou linux, ou
     * então baseado na versão da JVM.<br>
     *
     * @return {@link KeyStoreLoader}
     */
    public static KeyStoreLoader factoryKeyStoreLoader() {

        logger.debug("Fabricando KeyStore sem parametros");
        if (Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
            logger.debug("Fabricando KeyStore padrao Windows");
            if (Configuration.getInstance().isMSCapiDisabled()) {
                logger.debug("Fabricando KeyStore no modo PKCS11 para Windows");
                return new DriverKeyStoreLoader();
            } else {
                logger.debug("Fabricando KeyStore SunMSCAPI");
                return new MSKeyStoreLoader();
            }
        } else {
            logger.debug("Fabricando KeyStore no modo PKCS11 para Nao Windows");
            return new DriverKeyStoreLoader();
        }
    }

    /**
     * Método que fabrica uma instância de AbstractKeyStoreLoader para
     * manipulação de KeyStore padrão PKCS#12.
     *
     * @param file
     * @return {@link KeyStoreLoader}
     */
    public static KeyStoreLoader factoryKeyStoreLoader(File file) {
        return new FileSystemKeyStoreLoader(file);
    }

    /**
     * Método responsável por fabricar uma instância de AbstractKeyStoreLoader
     * baseado em uma classe passada como parâmetro.<br>
     * Representa um ponto de extensão do componente, o qual permite a aplicação
     * implementar seu próprio meio de carregamento de KeyStore.<br>
     *
     * @param clazz
     *
     * @return {@link KeyStoreLoader}
     */
    public static KeyStoreLoader factoryKeyStoreLoader(Class<? extends KeyStoreLoader> clazz) {

        if (clazz == null) {
            throw new KeyStoreLoaderException("O parametro \"clazz\" nao pode ser nulo");
        }
        KeyStoreLoader result = null;

        try {
            result = clazz.newInstance();

        } catch (IllegalAccessException | InstantiationException error) {
            throw new KeyStoreLoaderException("Erro na criacao da instancia de " + clazz.getCanonicalName());
        }
        return result;
    }
}
