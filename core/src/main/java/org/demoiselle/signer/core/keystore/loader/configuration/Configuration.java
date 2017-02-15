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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Classe responsável por recuperar informações do sistema tais como versão do
 * sistema operacional e versão da JVM.<br>
 * Manipula também informaões dos drivers PKCS#11 a serem utilizados pelo
 * componente.<br>
 * É possível adicionar um Driver PKCS#11 em tempo de execução, não restringindo
 * a utilização apenas dos drivers configurados no componente.
 */
public class Configuration {

    private static final Logger logger = LoggerFactory.getLogger(Configuration.class);
    protected static final String NAME_NULL = "Nome do driver deve ser informado";
    protected static final String PATH_NULL = "Path do driver deve ser informado";
    protected static final String PATH_INVALID = "Path do driver é inválido. O path deve conter o diretório e o nome do arquivo";
    protected static final String DRIVER_ERROR_LOAD = "Impossivel carregar o driver";
    protected static final String DRIVER_ERROR_LOAD_VARIABLE = "Impossivel carregar o driver definido na variavel de ambiente";
    protected static final String KEY_JAVA_VERSION = "java.runtime.version";
    protected static final String KEY_OS_NAME = "os.name";
    protected static final String VAR_PKCS11_CONFIG = "PKCS11_CONFIG_FILE";
    protected static final String VAR_PKCS11_DRIVER = "PKCS11_DRIVER";
    protected static final String CUSTOM_CONFIG_PATH = "user.home";
    protected static final String CUSTOM_CONFIG_FILENAME = "drivers.config";
    protected static final String FILE_SEPARATOR = "file.separator";
    protected static final String MSCAPI_DISABLED = "mscapi.disabled";
    protected static final String  CONFIG_FILE_DIR = ".signer";
    protected static final String  CONFIG_FILE_PATH = "drivers.properties";
    private static final Configuration instance = new Configuration();

    public static Configuration getInstance() {
        return Configuration.instance;
    }
    private final Map<String, String> drivers = new HashMap<>();

    private Configuration() {
        String winRoot = (System.getenv("SystemRoot") == null) ? "" : System.getenv("SystemRoot").replaceAll("\\\\", "/");
        Map<String, String> map = new HashMap<>();
        
        loadFromHomeFile(map);

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

        for (String driver : map.keySet()) {
            try {
                this.addDriver(driver, map.get(driver));
            } catch (Throwable error) {
                logger.error(DRIVER_ERROR_LOAD + " " + driver);
            }
        }

        try {
            this.getPKCS11DriverFromVariable();
        } catch (Throwable error) {
            logger.error(DRIVER_ERROR_LOAD);
        }

    }

    /**
     * Metodo que retorna a versao da JVM que esta rodando o componente. Busca
     * esta informacao nas propriedades do sistema.
     *
     * @return versao da JVM atual
     */
    public String getJavaVersion() {
        return System.getProperty(Configuration.KEY_JAVA_VERSION);
    }

    public boolean isMSCapiDisabled() {
        boolean enabled = Boolean.parseBoolean(this.getContentFromVariables(Configuration.MSCAPI_DISABLED));
        return enabled;
    }

    /**
     * Metodo que retorna o nome do sistema operacional. Busca esta informacao
     * nas propriedades do sistema.
     *
     * @return nome do sistema operacional atual
     */
    public String getSO() {
        return System.getProperty(Configuration.KEY_OS_NAME);
    }

    /**
     * Retorna um conjunto de drivers no padrão Map<'nome driver', 'path
     * driver'>
     *
     * @return
     */
    public Map<String, String> getDrivers() {
        return this.drivers;
    }

    /**
     * Testa cada driver informado, verificando se existe o arquivo. Caso o
     * arquivo do driver informado nao existe, nao sera acrescentado este driver
     * na lista de driver para ser carregado.
     *
     * @param name Parametro obrigatorio que informa o apelido do Driver a ser
     * carregado. Ex: Pronova
     * @param fileName Parametro obrigatorio que informa o path completo do
     * driver no sistema operacional. Ex: /etc/driver/driver.so
     */
    public void addDriver(String name, String fileName) {

        if (name == null || "".equals(name)) {
            throw new KeyStoreLoaderException(Configuration.NAME_NULL);
        }

        if (fileName == null || "".equals(fileName)) {
            throw new KeyStoreLoaderException(Configuration.PATH_NULL);
        }

        File file = new File(fileName);
        if (!file.exists() || !file.isFile()) {
            throw new KeyStoreLoaderException(Configuration.PATH_INVALID);
        }

        logger.debug("Adicionando o driver " + name + "::" + fileName + " na lista de drivers");
        this.drivers.put(name, fileName);

    }

    /**
     * O nome do driver é obrigatório para o devido carregamento da biblioteca,
     * mas não existe uma obrigatoriedade do nome ser sempre o mesmo e único,
     * então para facilitar nos casos em que não se saiba o fabricante do driver
     * pode-se utilizar este método que cria o nome do driver a partir do seu
     * arquivo fisico. Ex: /etc/driver/driver.so nome do driver = driver.so É
     * importante frisar que quanto maior for a informação melhor será para
     * corrigir problemas.
     *
     * @param fileName Parametro obrigatorio que informa o path completo do
     * driver no sistema operacional. Ex: /etc/driver/driver.so
     */
    public void addDriver(String fileName) {
        if (fileName == null || fileName.trim().length() <= 0) {
            throw new KeyStoreLoaderException("Nome do arquivo é requerido");
        }
        String driverName = fileName.replaceAll("\\\\", "/");
        int begin = driverName.lastIndexOf("/");
        begin = begin <= -1 ? 0 : begin + 1;
        int end = driverName.length();
        driverName = driverName.substring(begin, end);

        this.addDriver(driverName, fileName);

    }

    /**
     * Recuperar o path do arquivo de configuração para SunPKCS11 de acordo com
     * o site. Para utilizar o arquivo de configuracao, basta informar o seu
     * path em uma variavel de ambiente ou então como parametro da JVM Java 1.5
     * - http://java.sun.com/j2se/1.5.0/docs/guide/security/p11guide.html Java
     * 1.6 -
     * http://java.sun.com/javase/6/docs/technotes/guides/security/p11guide.html
     *
     * @return
     */
    public String getPKCS11ConfigFile() {
        String filePath = this.getContentFromVariables(Configuration.VAR_PKCS11_CONFIG);
        return filePath;
    }

    /**
     * Recuperar o driver e seu path a partir de variavel de ambiente ou
     * variavel da JVM. Exemplo de definicao: JVM:
     * -DPKCS11_DRIVER=Pronova::/usr/lib/libepsng_p11.so ou
     * -DPKCS11_DRIVER=/usr/lib/libepsng_p11.so Variavel de ambiente Linux
     * export PKCS11_DRIVER=Pronova::/usr/lib/libepsng_p11.so ou export
     * PKCS11_DRIVER=/usr/lib/libepsng_p11.so Variavel de ambiente windows set
     * PKCS11_DRIVER=Pronova::/WINDOWS/system32/ngp11v211.dll set
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
     * Busca nas variaveis de ambiente ou em variavel da JVM um determinado
     * valor. Prioridade para as variaveis de ambiente.
     *
     * @param key Chave de localizacao da variavel
     * @Creturn O conteudo definida em uma das variaveis. NULL se nenhuma
     * variavel for definida
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
    
    private void loadFromHomeFile(Map<String, String> map){
    	Properties prop = new Properties();
    	InputStream input = null;
    	
    	
    	try {
			input = new FileInputStream(Configuration.getConfigFilePath());
			prop.load(input);
			Set<String> keys = prop.stringPropertyNames();
			Iterator<String> it = keys.iterator();
			while (it.hasNext()){
				String key = it.next();
				map.put(key, prop.getProperty(key));
			}
		} catch (FileNotFoundException e) {
			new File(System.getProperty(CUSTOM_CONFIG_PATH)+System.getProperty(FILE_SEPARATOR)+CONFIG_FILE_DIR).mkdir();
			try {
				new File(Configuration.getConfigFilePath()).createNewFile();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			
		} catch (IOException e) {			
		}
   	
    }
    
    public static String getConfigFilePath(){
    	String separator = System.getProperty(FILE_SEPARATOR);
    	return System.getProperty(CUSTOM_CONFIG_PATH)+separator+CONFIG_FILE_DIR+separator+CONFIG_FILE_PATH;
    }

}
