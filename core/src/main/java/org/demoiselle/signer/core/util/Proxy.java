package org.demoiselle.signer.core.util;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

import org.apache.log4j.Logger;

public  final class Proxy {

	private static String proxyEndereco = null;
    private static String proxyPorta = null;
    private static String proxyUsuario = null;
    private static String proxySenha = null;
    private static MessagesBundle coreMessagesBundle = new MessagesBundle();
    private static final Logger LOGGER = Logger.getLogger(Proxy.class.getName());
    
	public Proxy() {
	}

	
	public static void setProxy()throws Exception {		
		try{
			if(proxyEndereco == null || proxyEndereco.trim().isEmpty() || proxyPorta == null || proxyPorta.trim().isEmpty() ){
				LOGGER.error(coreMessagesBundle.getString("error.proxy.empty.values",proxyEndereco,proxyPorta));
				throw new Exception(coreMessagesBundle.getString("error.proxy.empty.values",proxyEndereco,proxyPorta));
			}
			
			Authenticator.setDefault(
					   new Authenticator() {
					      @Override
					      public PasswordAuthentication getPasswordAuthentication() {
					         return new PasswordAuthentication(
					        		 proxyUsuario, proxySenha.toCharArray());
					      }
					   }
					);			
			System.setProperty("http.proxyHost", proxyEndereco);
			System.setProperty("http.proxyPort", proxyPorta);
			System.setProperty("http.proxyUser", proxyUsuario);
			System.setProperty("http.proxyPassword", proxySenha);
			System.setProperty("https.proxyHost", proxyEndereco);
			System.setProperty("https.proxyPort", proxyPorta);
			System.setProperty("https.proxyUser", proxyUsuario);
			System.setProperty("https.proxyPassword", proxySenha);
			LOGGER.info(coreMessagesBundle.getString("info.proxy.running",proxyEndereco,proxyPorta,proxyUsuario));

		}		
		catch (Exception e) {			
			LOGGER.error(coreMessagesBundle.getString("error.proxy",proxyEndereco,proxyPorta,proxyUsuario,e.getMessage()));
			throw new Exception(coreMessagesBundle.getString("error.proxy",proxyEndereco,proxyPorta,proxyUsuario,e.getMessage()));
		}		
	}

	
	
	public static String getProxyEndereco() {
		return proxyEndereco;
	}

	public static void setProxyEndereco(String proxyEndereco) {
		Proxy.proxyEndereco = proxyEndereco;
	}

	public static String getProxyPorta() {
		return proxyPorta;
	}

	public static void setProxyPorta(String proxyPorta) {
		Proxy.proxyPorta = proxyPorta;
	}

	public static String getProxyUsuario() {
		return proxyUsuario;
	}

	public static void setProxyUsuario(String proxyUsuario) {
		Proxy.proxyUsuario = proxyUsuario;
	}

	public static String getProxySenha() {
		return proxySenha;
	}

	public static void setProxySenha(String proxySenha) {
		Proxy.proxySenha = proxySenha;
	}

}
