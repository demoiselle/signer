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
package org.demoiselle.signer.core.keystore.loader.configuration;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.demoiselle.signer.core.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Class responsible for retrieving system information, such as operating system
 * version and JVM version. It also manipulates PKCS # 11 driver information to
 * be used by the component. You can add a PKCS # 11 Driver at run time, not
 * restricting the use of only the drivers configured on the component.
 *
 */
public class Configuration {

	private static final Logger logger = LoggerFactory.getLogger(Configuration.class);
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();
	protected static final String KEY_JAVA_VERSION = "java.runtime.version";
	protected static final String KEY_OS_NAME = "os.name";
	protected static final String VAR_PKCS11_CONFIG = "PKCS11_CONFIG_FILE";
	protected static final String VAR_PKCS11_DRIVER = "PKCS11_DRIVER";
	protected static final String CUSTOM_CONFIG_PATH = "user.home";
	protected static final String CUSTOM_CONFIG_FILENAME = "drivers.config";
	protected static final String FILE_SEPARATOR = "file.separator";
	protected static final String MSCAPI_DISABLED = "mscapi.disabled";
	protected static final String CONFIG_FILE_DIR = ".signer";
	protected static final String CONFIG_FILE_PATH = "drivers.properties";
	private static final Configuration instance = new Configuration();

	public static Configuration getInstance() {
		return Configuration.instance;
	}

	private final Map<String, String> drivers = new HashMap<>();

	/**
	 * Load driver for Token or SmartCard installed on local machine that will
	 * use this component Must to be installed on local machine and on the
	 * defined map bellow
	 */
	private Configuration() {
		String winRoot = (System.getenv("SystemRoot") == null) ? ""
				: System.getenv("SystemRoot").replaceAll("\\\\", "/");
		Map<String, String> map = new HashMap<>();

		loadFromHomeFile(map);

		// ------------ Windows ------------
		map.put("TokenOuSmartCard_00", winRoot.concat("/system32/ngp11v211.dll"));
		map.put("TokenOuSmartCard_01", winRoot.concat("/system32/aetpkss1.dll"));
		map.put("TokenOuSmartCard_02", winRoot.concat("/system32/gclib.dll"));
		map.put("TokenOuSmartCard_03", winRoot.concat("/system32/pk2priv.dll"));
		map.put("TokenOuSmartCard_04", winRoot.concat("/system32/w32pk2ig.dll"));
		map.put("TokenOuSmartCard_05", winRoot.concat("/system32/eTPkcs11.dll"));
		map.put("TokenOuSmartCard_06", winRoot.concat("/system32/acospkcs11.dll"));
		map.put("TokenOuSmartCard_07", winRoot.concat("/system32/dkck201.dll"));
		map.put("TokenOuSmartCard_08", winRoot.concat("/system32/dkck232.dll"));
		map.put("TokenOuSmartCard_09", winRoot.concat("/system32/cryptoki22.dll"));
		map.put("TokenOuSmartCard_10", winRoot.concat("/system32/acpkcs.dll"));
		map.put("TokenOuSmartCard_11", winRoot.concat("/system32/slbck.dll"));
		map.put("TokenOuSmartCard_12", winRoot.concat("/system32/cmP11.dll"));
		map.put("TokenOuSmartCard_13", winRoot.concat("/system32/WDPKCS.dll"));
		map.put("TokenOuSmartCard_14", winRoot.concat("/System32/Watchdata/Watchdata Brazil CSP v1.0/WDPKCS.dll"));
		map.put("TokenOuSmartCard_15", "/Arquivos de programas/Gemplus/GemSafe Libraries/BIN/gclib.dll");
		map.put("TokenOuSmartCard_16", "/Program Files/Gemplus/GemSafe Libraries/BIN/gclib.dll");

		// ------------ Linux ------------
		map.put("TokenOuSmartCard_17", "/usr/lib/libaetpkss.so");
		map.put("TokenOuSmartCard_18", "/usr/lib/libgpkcs11.so");
		map.put("TokenOuSmartCard_19", "/usr/lib/libgpkcs11.so.2");

		// Token Verde do Serpro
		map.put("TokenOuSmartCard_20", "/usr/lib/libepsng_p11.so");
		map.put("TokenOuSmartCard_21", "/usr/lib/libepsng_p11.so.1");
		map.put("TokenOuSmartCard_22", "/usr/local/ngsrv/libepsng_p11.so.1");

		// Token Azul do Serpro
		map.put("TokenOuSmartCard_23", "/usr/lib/libeTPkcs11.so");
		map.put("TokenOuSmartCard_24", "/usr/lib/libeToken.so");
		map.put("TokenOuSmartCard_25", "/usr/lib/libeToken.so.4");
		map.put("TokenOuSmartCard_26", "/usr/lib/libcmP11.so");
		map.put("TokenOuSmartCard_27", "/usr/lib/libwdpkcs.so");
		map.put("TokenOuSmartCard_28", "/usr/local/lib64/libwdpkcs.so");
		map.put("TokenOuSmartCard_29", "/usr/local/lib/libwdpkcs.so");
		map.put("TokenOuSmartCard_30", "/usr/lib/watchdata/ICP/lib/libwdpkcs_icp.so");
		map.put("TokenOuSmartCard_31", "/usr/lib/watchdata/lib/libwdpkcs.so");
		map.put("TokenOuSmartCard_32", "/opt/watchdata/lib64/libwdpkcs.so");
		map.put("TokenOuSmartCard_33", "/usr/lib/opensc-pkcs11.so");
		map.put("TokenOuSmartCard_34", "/usr/lib/pkcs11/opensc-pkcs11.so");
		map.put("TokenOuSmartCard_35", "/usr/lib/libwdpkcs.dylib");
		map.put("TokenOuSmartCard_36", "/usr/local/lib/libwdpkcs.dylib");
		map.put("TokenOuSmartCard_37", "/usr/local/ngsrv/libepsng_p11.so.1.2.2");
		
		// ------------ Mac ------------
		// Token Branco do Serpro
		map.put("TokenOuSmartCard_38",
				"//Applications//WatchKey USB Token Admin Tool.app//Contents//MacOS//lib//libWDP11_BR_GOV.dylib");
		map.put("TokenOuSmartCard_39",
				"//usr//local//lib//libetpkcs11.dylib");
		map.put("TokenOuSmartCard_40",
				"//usr//local//lib//libaetpkss.dylib");
		
		// Certificado em Nuvem - Windows
		map.put("TokenOuSmartCard_41", winRoot.concat("/system32/SerproPkcs11.dll"));
		map.put("TokenOuSmartCard_42", winRoot.concat("/usr/lib/libneoidp11.so"));
		
		

		boolean successLoad = false;
		for (String driver : map.keySet()) {
			try {
				this.addDriver(driver, map.get(driver));
				logger.info(coreMessagesBundle.getString("info.load.driver", driver));
				successLoad = true;
			} catch (Throwable error) {
				logger.debug(coreMessagesBundle.getString("error.load.driver", driver));
			}
		}

		if (!successLoad) {
			logger.error(coreMessagesBundle.getString("error.load.driver.null"));
		}

		try {
			this.getPKCS11DriverFromVariable();
		} catch (Throwable error) {
			logger.error(coreMessagesBundle.getString("error.load.driver.null"));
		}

	}

	/**
	 * Method that returns the version of the JVM that is running the component.
	 * Look for this information in the system properties.
	 *
	 * @return version of current JVM
	 */
	public String getJavaVersion() {
		return System.getProperty(Configuration.KEY_JAVA_VERSION);
	}

	/**
	 * 
	 * @return true if Microsoft CryptoAPI is DISABLE
	 */
	public boolean isMSCapiDisabled() {
		boolean enabled = Boolean.parseBoolean(this.getContentFromVariables(Configuration.MSCAPI_DISABLED));
		return enabled;
	}

	/**
	 * Method that returns the name of the operating system. Look for this
	 * information in the system properties.
	 *
	 * @return name of the operating system
	 */
	public String getSO() {
		return System.getProperty(Configuration.KEY_OS_NAME);
	}

	/**
	 * Returns a set of drivers in the Map, in this pattern: <'driver name',
	 * 'path driver'>
	 *
	 * @return
	 */
	public Map<String, String> getDrivers() {
		return this.drivers;
	}

	/**
	 * Tests each driver that has been informed, checking if the file exists. If
	 * the driver file you entered does not exist, this driver will not be added
	 * to the list to be loaded.
	 *
	 * @param name
	 *            Required parameter that informs the driver's nickname to be
	 *            loaded. Ex: Pronova
	 * @param fileName
	 *            Mandatory parameter that informs the full path of the driver
	 *            in the operating system. Ex: /etc/driver/driver.so
	 */
	public void addDriver(String name, String fileName) {

		if (name == null || "".equals(name)) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.name.null"));
		}

		if (fileName == null || "".equals(fileName)) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.driver.null"));
		}

		File file = new File(fileName);
		if (!file.exists() || !file.isFile()) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.path.invalid"));
		}

		logger.debug(coreMessagesBundle.getString("info.add.driver", name, fileName));
		this.drivers.put(name, fileName);

	}

	/**
	 * The name of the driver is required for proper loading of the library, but
	 * there is no obligation for the name to be always the same and unique, so
	 * to facilitate in cases where the manufacturer of the driver is not known,
	 * this method can be used to create the Name of the driver from your
	 * physical file. Ex: /etc/driver/driver.so driver name = driver.so It is
	 * important to point out that the higher the information the better it will
	 * be to avoid problems.
	 *
	 * @param fileName
	 *            Mandatory parameter that informs the full path of the driver
	 *            in the operating system. Ex: /etc/driver/driver.so
	 */
	public void addDriver(String fileName) {
		if (fileName == null || fileName.trim().length() <= 0) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("warn.file.null"));
		}
		String driverName = fileName.replaceAll("\\\\", "/");
		int begin = driverName.lastIndexOf("/");
		begin = begin <= -1 ? 0 : begin + 1;
		int end = driverName.length();
		driverName = driverName.substring(begin, end);

		this.addDriver(driverName, fileName);

	}

	/**
	 * Retrieve the path of the configuration file for SunPKCS11 according to
	 * the links below. To use the configuration file, simply enter your path in
	 * an environment variable or as a JVM parameter
	 * 
	 * Java 1.5 -
	 * http://java.sun.com/j2se/1.5.0/docs/guide/security/p11guide.html Java
	 * Java 1.6 -
	 * http://java.sun.com/javase/6/docs/technotes/guides/security/p11guide.html
	 * Java 7 -
	 * http://docs.oracle.com/javase/7/docs/technotes/guides/security/p11guide.html
	 * Java 8 -
	 * https://docs.oracle.com/javase/8/docs/technotes/guides/security/p11guide.html
	 *
	 * @return
	 */
	public String getPKCS11ConfigFile() {
		String filePath = this.getContentFromVariables(Configuration.VAR_PKCS11_CONFIG);
		return filePath;
	}

	/**
	 * Retrieve the driver and its path from the environment variable or JVM
	 * variable.
	 * 
	 * Example of definition:
	 * 
	 * JVM: -DPKCS11_DRIVER=Pronova::/usr/lib/libepsng_p11.so or
	 * -DPKCS11_DRIVER=/usr/lib/libepsng_p11.so
	 * 
	 * Environment variable in Linux export
	 * PKCS11_DRIVER=Pronova::/usr/lib/libepsng_p11.so ou export
	 * PKCS11_DRIVER=/usr/lib/libepsng_p11.so Environment variable in window$
	 * set PKCS11_DRIVER=Pronova::/WINDOWS/system32/ngp11v211.dll set
	 * PKCS11_DRIVER=/WINDOWS/system32/ngp11v211.dll
	 */
	public void getPKCS11DriverFromVariable() {

		String driverInfo = this.getContentFromVariables(Configuration.VAR_PKCS11_DRIVER);

		if (driverInfo != null) {

			if (driverInfo.lastIndexOf("::") > 0) {
				String[] driverInfoSplited = driverInfo.split("::");
				if (driverInfoSplited.length == 2) {
					this.addDriver(driverInfoSplited[0], driverInfoSplited[1]);
				}
			} else {
				this.addDriver(driverInfo);
			}

		}

	}

	/**
	 * Search the environment variables or a JVM variable for a given value.
	 * Priority for environment variables.
	 *
	 * @param key
	 *            Variable location key
	 * @return The content defined in one of the variables. NULL if no variables
	 *         are defined
	 */
	private String getContentFromVariables(String key) {
		String content = System.getenv(key);
		if (content == null) {
			content = System.getenv(key.toLowerCase());
		}
		if (content == null) {
			content = System.getenv(key.toUpperCase());
		}

		if (content == null) {
			content = System.getProperty(key);
		}
		if (content == null) {
			content = System.getProperty(key.toLowerCase());
		}
		if (content == null) {
			content = System.getProperty(key.toUpperCase());
		}

		if (content == null) {
			String filename = System.getProperty(CUSTOM_CONFIG_PATH) + System.getProperty(FILE_SEPARATOR)
					+ CUSTOM_CONFIG_FILENAME;
			boolean exists = (new File(filename)).exists();
			if (exists) {
				content = filename;
			}
		}

		return content;
	}

	/**
	 * 
	 * load configuration drivers from a file storaged on user machine
	 * 
	 * @param map
	 */
	private void loadFromHomeFile(Map<String, String> map) {
		Properties prop = new Properties();
		InputStream input = null;

		try {
			input = new FileInputStream(Configuration.getConfigFilePath());
			prop.load(input);
			Set<String> keys = prop.stringPropertyNames();
			Iterator<String> it = keys.iterator();
			while (it.hasNext()) {
				String key = it.next();
				map.put(key, prop.getProperty(key));
			}
		} catch (FileNotFoundException e) {
			new File(System.getProperty(CUSTOM_CONFIG_PATH) + System.getProperty(FILE_SEPARATOR) + CONFIG_FILE_DIR)
					.mkdir();
			try {
				new File(Configuration.getConfigFilePath()).createNewFile();
			} catch (IOException e1) {
				e1.printStackTrace();
			}

		} catch (IOException e) {
		}

	}

	/**
	 * 
	 * @return File path acording to SO
	 */
	public static String getConfigFilePath() {
		String separator = System.getProperty(FILE_SEPARATOR);
		return System.getProperty(CUSTOM_CONFIG_PATH) + separator + CONFIG_FILE_DIR + separator + CONFIG_FILE_PATH;
	}

}
