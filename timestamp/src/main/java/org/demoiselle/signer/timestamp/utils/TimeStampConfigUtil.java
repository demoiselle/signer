package org.demoiselle.signer.timestamp.utils;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generates the required settings for time stamp request.
 * Depending on the files: timestamp-config.properties or timestamp-config-default.properties.
 */
public class TimeStampConfigUtil {

	private static final Logger logger = LoggerFactory.getLogger(TimeStampConfigUtil.class);

	private static TimeStampConfigUtil instance = null;
	private static ResourceBundle bundle = null;
	private static MessagesBundle timeStampMessagesBundle = new MessagesBundle();

	private String tspHostname = "act.serpro.gov.br";
	private int tspPort = 318;
	private String tspOid= "2.16.76.1.6.2";
	private String apiAuthUrl="https://gateway.apiserpro.serpro.gov.br/token";
	private String apiEndpointUrl="https://gateway.apiserpro.serpro.gov.br/apitimestamp-trial/v1";

	/**
	 * @return Returns an instance of TimeStampConfig
	 */
	public static TimeStampConfigUtil getInstance() {
		if (instance == null) {
			instance = new TimeStampConfigUtil();
		}
		return instance;
	}

	public ResourceBundle getBundle(String bundleName) {
		return ResourceBundle.getBundle(bundleName);
	}

	protected TimeStampConfigUtil() {
		if (bundle == null) {
			try {
				bundle = getBundle("timestamp-config");
			} catch (MissingResourceException mre) {
				try {
					bundle = getBundle("timestamp-config-default");
				} catch (MissingResourceException e) {
					logger.error(e.getMessage());
				}
			}
		}
	}

	public String getTspHostname() {
		try {
			String varTspHostname = bundle.getString("tsp_hostname");
			if (varTspHostname!= null && !varTspHostname.isEmpty() && varTspHostname.length() >1) {
				tspHostname = varTspHostname;
			}
		} catch (MissingResourceException e) {
			logger.error(timeStampMessagesBundle.getString("error.timestamp.config", "tspHostname"));
		}
		return tspHostname;
	}

	public int getTSPPort() {
		try {
			int varTspPort = Integer.parseInt(bundle.getString("tsp_port"));
			if (varTspPort > 0) {
				tspPort = varTspPort;
			}
		} catch (MissingResourceException e) {
			logger.error(timeStampMessagesBundle.getString("error.timestamp.config", "tspPort"));
		}
		return tspPort;
	}

	public String getTSPOid() {
		try {
			String varTspOid = bundle.getString("tsp_oid");
			if (varTspOid!= null && !varTspOid.isEmpty() && varTspOid.length() >1) {
				tspOid =varTspOid;
			}			
		} catch (MissingResourceException e) {
			logger.error(timeStampMessagesBundle.getString("error.timestamp.config", "tspOid"));
		}
		return tspOid;
	}

	public String getApiAuthUrl() {
		try {
			String varApiAuthUrl = bundle.getString("api_auth_url");
			if (varApiAuthUrl!= null && !varApiAuthUrl.isEmpty() && varApiAuthUrl.length() >1) {
				apiAuthUrl =varApiAuthUrl;
			}		 
		} catch (MissingResourceException e) {
			logger.error(timeStampMessagesBundle.getString("error.timestamp.config", "api_auth_url"));
		}
		return apiAuthUrl;
	}

	public void setApiAuthUrl(String apiAuthUrl) {
		this.apiAuthUrl = apiAuthUrl;
	}

	public String getApiEndpointUrl() {
		try {
			String varApiEndpointUrl = bundle.getString("api_endpoint_url");
			if (varApiEndpointUrl!= null && !varApiEndpointUrl.isEmpty() && varApiEndpointUrl.length() >1) {
				apiEndpointUrl =varApiEndpointUrl;
			}
		} catch (MissingResourceException e) {
			logger.error(timeStampMessagesBundle.getString("error.timestamp.config", "api_endpoint_url"));
		}
		return apiEndpointUrl;
	}

	public void setApiEndpointUrl(String apiEndpointUrl) {
		this.apiEndpointUrl = apiEndpointUrl;
	}
}
