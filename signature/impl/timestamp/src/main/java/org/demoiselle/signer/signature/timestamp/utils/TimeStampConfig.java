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
package org.demoiselle.signer.signature.timestamp.utils;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class TimeStampConfig {

    private static final Logger logger = LoggerFactory.getLogger(TimeStampConfig.class);

    private static TimeStampConfig instance = null;
    private static ResourceBundle bundle = null;
    
    private String tspHostname;
    private int tspPort;
    private String tspOid;
    
    /**
     * Retorna uma instancia de TimeStampConfig
     *
     * @return a instância
     */
    public static TimeStampConfig getInstance() {
        if (instance == null) {
            instance = new TimeStampConfig();
        }
        return instance;
    }

    public ResourceBundle getBundle(String bundleName) {
        return ResourceBundle.getBundle(bundleName);
    }    

    protected TimeStampConfig() {
        if (bundle == null){
	    	try {
	        	bundle = getBundle("timestamp-config");
	        } catch (MissingResourceException mre) {
	            try {
	            	bundle = getBundle("timestamp-config-default");
	            } catch (MissingResourceException e) {
	            	 logger.info(e.getMessage());
	            }
	        }
        }
    }

    public String getTspHostname() {
    	try {
    		tspHostname = bundle.getString("tsp_hostname");
		} catch (MissingResourceException e) {
			throw new RuntimeException("key 'tspHostname' not found for resource");
		}
    	return tspHostname;
    }

    public int getTSPPort() {
    	try {
			tspPort = Integer.parseInt(bundle.getString("tsp_port"));
		} catch (MissingResourceException e) {
			throw new RuntimeException("key 'tspPort' not found for resource");
		}
    	return tspPort;
    }

    public String getTSPOid() {
    	try {
    		tspOid =  bundle.getString("tsp_oid");
		} catch (MissingResourceException e) {
			throw new RuntimeException("key 'tspOid' not found for resource");
		}
    	return tspOid;
    }
}
