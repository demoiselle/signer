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
package org.demoiselle.signer.core.repository;

import java.io.File;
import java.net.Authenticator;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Configuration {
	

	private static final Logger LOGGER = LoggerFactory.getLogger(Configuration.class);

    /**
     * System key to set online or offline mode
     */
    public static final String MODE_ONLINE = "signer.repository.online";

    
    /**
     * System environment key to set online or offline mode
     */
    public static final String ENV_MODE_ONLINE = "SIGNER_REPOSITORY_ONLINE";

    /**
     * System key to set storage location of index file of revoked certificate lists.
     */
    public static final String CRL_INDEX = "signer.repository.crl.index";

    
    /**
     * System environment key to set storage location of index file of revoked certificate lists.
     */
    public static final String ENV_CRL_INDEX = "SIGNER_REPOSITORY_CRL_INDEX";

    /**
     * System key to set storage location of path file of revoked certificate lists.
     */
    public static final String CRL_PATH = "signer.repository.crl.path";
    
    
    /**
     * System environment key to set storage location of path file of revoked certificate lists.
     */
    public static final String ENV_CRL_PATH = "SIGNER_REPOSITORY_CRL_PATH";
    
    
    /**
     * System key to set storage location of path file of LPA 
     */
    public static final String LPA_PATH = "signer.repository.lpa.path";
    
    
    /**
     * System environment key to set storage location of path file of LPA 
     */
    public static final String ENV_LPA_PATH = "SIGNER_REPOSITORY_LPA.PATH";
    
        
    /**
     * System key to set online only mode to get LPA 
     */
    public static final String LPA_ONLINE = "signer.repository.lpa.online";
    
    /**
     * System environment key to set online only mode to get LPA 
     */
    public static final String ENV_LPA_ONLINE = "SIGNER_REPOSITORY_LPA_ONLINE";
    
    
    /**
     * System key to set host of settings proxy
     */
    public static final String PROXY_HOST = "signer.proxy.host";
    
    
    /**
     * System environment key to set host of settings proxy
     */
    public static final String ENV_PROXY_HOST = "SIGNER_PROXY_HOST";
    
    /**
     * System  key to set host of settings proxy
     */
    public static final String PROXY_PORT = "signer.proxy.port";
    
    /**
     * System environment key to set host of settings proxy
     */
    public static final String ENV_PROXY_PORT = "SIGNER_PROXY_PORT";

    /**
     * System key to set host of settings proxy
     */
    public static final String PROXY_USER = "signer.proxy.user";
    
    /**
     * System environment key to set host of settings proxy
     */
    public static final String ENV_PROXY_USER = "SIGNER_PROXY_USER";

    /**
     * System key to set host of settings proxy
     */
    public static final String PROXY_PASSWORD = "signer.proxy.password";

    /**
     * System environment key to set host of settings proxy
     */
    public static final String ENV_PROXY_PASSWORD = "SIGNER_PROXY_PASSWORD";

    /**
     * System  key to set host of settings proxy
     */
    public static final String PROXY_TYPE = "signer.proxy.type";
    
    /**
     * System environment key to set host of settings proxy
     */
    public static final String ENV_PROXY_TYPE = "SIGNER_PROXY_TYPE";
    
    
    public static Configuration instance = new Configuration();

    
    /**
     * to static single instance
     *
     * @return instance of Configuration
     */
    public static Configuration getInstance() {
        return instance;
    }

    private String crlIndex = null;
    private String crlPath = null;
    private String lpaPath = null;    
    private boolean isOnline = true;
    private Proxy proxy = null;
    private Proxy.Type type = null;
    private boolean isOnlineLPA = false;

    /**
     * Check for system variables. If there is, assign in class variables otherwise use default values.
     */
    private Configuration() {
    	
        String mode_online = (String) System.getenv(MODE_ONLINE);
        if (mode_online == null || mode_online.isEmpty()) {
        	mode_online = (String) System.getProperties().get(MODE_ONLINE);
        	LOGGER.debug("CRL was set default : true");
            setOnline(true);
        } else {
            setOnline(Boolean.valueOf(mode_online));
        }
        
        crlIndex =  (String) System.getenv(CRL_INDEX);
        if (crlIndex == null || crlIndex.isEmpty()) {
        	crlIndex =  (String) System.getProperties().get(CRL_INDEX);
        	if (crlIndex == null || crlIndex.isEmpty()) {
        		LOGGER.debug("CRL index was set default : .crl_index");
        		setCrlIndex(".crl_index");
        	}            
        }

        crlPath = (String) System.getenv(CRL_PATH);
        if (crlPath == null || crlPath.isEmpty()) {
        	crlPath = (String) System.getProperties().get(CRL_PATH);
        	if (crlPath == null || crlPath.isEmpty()) {
        		LOGGER.debug("CRL PATH was set default : java.io.tmpdir+crls" );
        		setCrlPath(System.getProperty("java.io.tmpdir") + File.separatorChar + "crls");
        	}
        }
        
        lpaPath = (String) System.getenv(ENV_LPA_PATH); 
        if (lpaPath == null || lpaPath.isEmpty()) {
        	lpaPath = (String) System.getProperties().get(LPA_PATH);
        	if (lpaPath == null || lpaPath.isEmpty()) {
        		LOGGER.debug("LPA PATH was set default : java.io.tmpdir+crls" );
        		setLpaPath(System.getProperty("java.io.tmpdir") + File.separatorChar + "lpas");	
        	}            
        }
        
        String hostName = (String) System.getenv(PROXY_HOST);
        if (hostName == null || hostName.isEmpty()) {
        	hostName = (String) System.getProperties().get(PROXY_HOST);
        	if (hostName == null || hostName.isEmpty()) {
        		setProxy(Proxy.NO_PROXY);	
        		LOGGER.debug("Proxy was set to NO_PROXY" );
        	}else {
            	String proxyType = (String) System.getProperties().get(PROXY_TYPE);
            	setType(proxyType);            	
            	String port = (String) System.getProperties().get(PROXY_PORT);
            	String user = (String) System.getProperties().get(PROXY_USER);
            	String password = (String) System.getProperties().get(PROXY_PASSWORD);
            	setProxy(hostName, port, user, password);
            	LOGGER.debug("Proxy was set: "+hostName+port);
            }        	
        } else {
        	String proxyType = (String) System.getenv(PROXY_TYPE);
        	setType(proxyType);
        	String port = (String) System.getenv(PROXY_PORT);
        	String user = (String) System.getenv(PROXY_USER);
        	String password = (String) System.getenv(PROXY_PASSWORD);
        	setProxy(hostName, port, user, password);
        	LOGGER.debug("Proxy was set: "+hostName+port);
        }
        
        String lpa_online = (String) System.getenv(ENV_LPA_ONLINE);
        // default is false if not seted
        if (lpa_online == null || lpa_online.isEmpty()) {
        	lpa_online = (String) System.getProperties().get(LPA_ONLINE);
        	if (lpa_online == null || lpa_online.isEmpty()) {
        		LOGGER.debug("LPA mode was set to default FALSE ");
        		setOnlineLPA(false);
        	}else{
        		setOnlineLPA(Boolean.valueOf(lpa_online));
        	}        		
        } else {
            setOnlineLPA(Boolean.valueOf(lpa_online));
        }
    }

    /**
     * Gets the location where the revoked certificate lists index file is stored
     *
     * @return location of CRL index file, default is .crl_index
     */
    public String getCrlIndex() {
        return crlIndex;
    }

    public void setCrlIndex(String crlIndex) {
        this.crlIndex = crlIndex;
    }

    /**
     * Returns whether the repository is in online (TRUE) or offline (FALSE) mode
     * Default is TRUE 
     *
     * @return true (online) or false (offline)
     */
    public boolean isOnline() {
        return isOnline;
    }

    /**
     * Determines whether the repository query should be done online or offline.
     *
     * @param isOnline True for online, False for offline.
     */
    public void setOnline(boolean isOnline) {
        this.isOnline = isOnline;
    }

    /**
     * Retrieves the location where the CRL(certificate revoked lists) repository is stored
     *
     * Default is "java.io.tmpdir" + "crls"
     * @return location of CRL repository 
     */
    public String getCrlPath() {
        return crlPath;
    }

    /**
     * Configures the location where the CRL (certificate revoked lists) repository will be stored
     *
     * @param crlPath path for CRL repository
     */
    public void setCrlPath(String crlPath) {
        this.crlPath = crlPath;
    }

    /** Retrieves the location where the LPA local repository is stored
     * 
     * Default is "java.io.tmpdir" + "lpas"
     * @return location of local LPA repository
     */
	public String getLpaPath() {
		return lpaPath;
	}
	
	/**
	 * 
	 *  Configures the location where the LPA local repository will be stored
	 *  
	 * @param lpaPath path for LPA local repository
	 */

	public void setLpaPath(String lpaPath) {
		this.lpaPath = lpaPath;
	}

	/**
	 * 
	 * @return  Proxy was set
	 */
	public Proxy getProxy() {
		return proxy;
	}

	public void setProxy(Proxy proxy) {
		this.proxy = proxy;
	}
	
	/**
	 * 
	 * @return Proxy.Type was set
	 */
	public Proxy.Type getType() {
		return type;
	}

	public void setType(String type) {
		if (type == null || type.isEmpty()) {
			this.type = Proxy.Type.HTTP;
        } else {
        	this.type = Proxy.Type.valueOf(type.toUpperCase());
        }
	}

	/**
	 * Configure Proxy
	 * 
	 * @param hostName
	 * @param port
	 * @param userName
	 * @param password
	 */
	public void setProxy(String hostName, String port, final String userName, final String password) {
		try {
			InetAddress inetAddress = InetAddress.getByName(hostName);
			SocketAddress socketAddress = new InetSocketAddress(inetAddress, Integer.parseInt(port));
			this.proxy = new Proxy(type, socketAddress);
			if (userName == null || userName.isEmpty()) {
				Authenticator authenticator = new Authenticator() {
					public PasswordAuthentication getPasswordAuthentication() {
						return (new PasswordAuthentication(userName, password.toCharArray()));
					}
				};
				Authenticator.setDefault(authenticator);
	        }
		} catch(UnknownHostException uhe) {
			LOGGER.error("Error setting:"+hostName+port +"\n"+uhe.getMessage());
			this.proxy = Proxy.NO_PROXY;
		}
	}

	/**
	 * 
	 * @return if LPA recovery mode is online
	 */
	public boolean isOnlineLPA() {
		return isOnlineLPA;
	}

	public void setOnlineLPA(boolean isOnlineLPA) {
		this.isOnlineLPA = isOnlineLPA;
	}
}
