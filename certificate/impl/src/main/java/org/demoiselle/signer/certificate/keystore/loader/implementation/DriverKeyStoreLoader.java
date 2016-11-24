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
package org.demoiselle.signer.certificate.keystore.loader.implementation;

import org.demoiselle.signer.certificate.keystore.loader.DriverNotAvailableException;
import org.demoiselle.signer.certificate.keystore.loader.InvalidPinException;
import org.demoiselle.signer.certificate.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.certificate.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.certificate.keystore.loader.PKCS11NotFoundException;
import org.demoiselle.signer.certificate.keystore.loader.configuration.Configuration;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Formatter;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementação de KeyStoreLoader baseado em drivers do sistema operacional. É
 * necessário informar o arquivo do driver no sistema operacional e o nome da
 * API.
 */
public class DriverKeyStoreLoader implements KeyStoreLoader {

    private static final Logger logger = LoggerFactory.getLogger(DriverKeyStoreLoader.class);
    private static final String PINNUMBER_INVALID = "PIN access to token can not be null or invalid";
    private static final String DRIVER_LOAD_ERROR = "Error on load a module PKCS#11";
    private static final String DRIVERS_EMPTY = "No driver are available";
    private static final String DRIVERS_NOT_COMPATIBLE = "No driver in the list is compatible with your hardware";
    private static final String PKCS11_KEYSTORE_TYPE = "PKCS11";
    private static final String PKCS11_CONTENT_CONFIG_FILE = "name = %s\nlibrary = %s";
    private CallbackHandler callback;

    @Override
    public KeyStore getKeyStore() {
        String configFile = Configuration.getInstance().getPKCS11ConfigFile();

        if (configFile != null) {
            return this.getKeyStoreFromConfigFile(configFile);
        } else {
            return this.getKeyStoreFromDrivers();
        }
    }

    public KeyStore getKeyStoreFromDriver(String driverPath) {

        String driverName = driverPath.replaceAll("\\\\", "/");
        int begin = driverName.lastIndexOf("/");
        begin = begin <= -1 ? 0 : begin + 1;
        int end = driverName.length();
        driverName = driverName.substring(begin, end);

        return this.getKeyStoreFromDriver(driverName, driverPath);

    }

    public KeyStore getKeyStoreFromDriver(String driverName, String driverPath) {
        Configuration.getInstance().addDriver(driverName, driverPath);
        KeyStore keyStore = null;
        String pkcs11ConfigSettings = (new Formatter()).format(PKCS11_CONTENT_CONFIG_FILE, driverName, driverPath).toString();
        byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
        ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);

        try {
            Constructor<?> construtor = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(new Class[]{InputStream.class});
            Provider pkcs11Provider = (Provider) construtor.newInstance(new Object[]{confStream});
            Security.addProvider(pkcs11Provider);
            confStream.close();
            Method login = Class.forName("sun.security.pkcs11.SunPKCS11").getMethod("login", new Class[]{Subject.class, CallbackHandler.class});
            login.invoke(Security.getProvider(pkcs11Provider.getName()), new Object[]{null, this.callback});
            keyStore = KeyStore.getInstance(PKCS11_KEYSTORE_TYPE, pkcs11Provider.getName());
            keyStore.load(null, null);

        } catch (IOException | ClassNotFoundException | IllegalAccessException | IllegalArgumentException | InstantiationException | NoSuchMethodException | SecurityException | InvocationTargetException | KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException ex) {
            if (ex.getCause().toString().equals("javax.security.auth.login.FailedLoginException")) {
                throw new InvalidPinException(PINNUMBER_INVALID, ex);
            }

            if (ex.getCause().toString().equals("javax.security.auth.login.LoginException")) {
                throw new InvalidPinException(PINNUMBER_INVALID, ex);
            } else {
                throw new PKCS11NotFoundException(DRIVER_LOAD_ERROR, ex);
            }
        }
        return keyStore;
    }

    private KeyStore getKeyStoreFromConfigFile(String configFile) {

        KeyStore keyStore = null;

        try {
            Constructor<?> construtor = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(new Class[]{String.class});
            Provider pkcs11Provider = (Provider) construtor.newInstance(new Object[]{configFile});
            Security.addProvider(pkcs11Provider);
            Method login = Class.forName("sun.security.pkcs11.SunPKCS11").getMethod("login", new Class[]{Subject.class, CallbackHandler.class});
            login.invoke(Security.getProvider(pkcs11Provider.getName()), new Object[]{null, this.callback});
            keyStore = KeyStore.getInstance(PKCS11_KEYSTORE_TYPE, pkcs11Provider.getName());
            keyStore.load(null, null);

        } catch (IOException | ClassNotFoundException | IllegalAccessException | IllegalArgumentException | InstantiationException | NoSuchMethodException | SecurityException | InvocationTargetException | KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException ex) {
            if (ex.getCause().toString().equals("javax.security.auth.login.FailedLoginException")) {
                throw new InvalidPinException(PINNUMBER_INVALID, ex);
            }

            if (ex.getCause().toString().equals("javax.security.auth.login.LoginException")) {
                throw new InvalidPinException(PINNUMBER_INVALID, ex);
            } else {
                throw new PKCS11NotFoundException(DRIVER_LOAD_ERROR, ex);
            }
        }
        return keyStore;
    }

    private KeyStore getKeyStoreFromDrivers() {
        KeyStoreLoaderException error = new KeyStoreLoaderException(DRIVERS_NOT_COMPATIBLE);
        Map<String, String> drivers = Configuration.getInstance().getDrivers();

        if (drivers == null || drivers.isEmpty()) {
            throw new DriverNotAvailableException(DRIVERS_EMPTY);
        }

        Set<String> keyDrivers = drivers.keySet();
        KeyStore keyStore = null;

        for (String driver : keyDrivers) {
            try {
                String urlDriver = drivers.get(driver);
                keyStore = this.getKeyStoreFromDriver(driver, urlDriver);
                break;
            } catch (PKCS11NotFoundException e) {
                error.addError(e);
            } catch (InvalidPinException e) {
                throw e;
            } catch (Throwable erro) {
                error.addError(erro);
            }
        }

        if (keyStore == null && error.hasErrors()) {
            throw error;
        }

        return keyStore;
    }

    @Override
    public void setCallbackHandler(CallbackHandler callback) {
        this.callback = callback;
    }

}
