package org.demoiselle.signer.policy.impl.xades.xml;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import org.demoiselle.signer.core.timestamp.TimeStampGenerator;
import org.demoiselle.signer.core.timestamp.TimeStampGeneratorSelector;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XMLTimeStampToken {
	private static final Logger logger = LoggerFactory.getLogger(XMLTimeStampToken.class);
	private static final TimeStampGenerator timeStampGenerator = TimeStampGeneratorSelector.selectReference();
    private static MessagesBundle xadesMessagesBundle = new MessagesBundle();
    private PrivateKey privateKey = null;
    private Certificate[] certificates = null;
    private byte[] content = null;
    private byte[] hash = null;
    
    
	public XMLTimeStampToken(PrivateKey privateKey, Certificate[] certificates, byte[] content, byte[] hash) {
		super();
		this.privateKey = privateKey;
		this.certificates = certificates;
		this.content = content;
		this.hash = hash;
	}
	
	public byte[] getTimeStampToken() throws SignerException {
		byte[] response = null;
        try {
            logger.debug(xadesMessagesBundle.getString("info.tsa.connecting"));

            if (timeStampGenerator != null) {
                  //Inicializa os valores para o timestmap
            	timeStampGenerator.initialize(content, privateKey, certificates, hash);

                //Obtem o carimbo de tempo atraves do servidor TSA
                response = timeStampGenerator.generateTimeStamp();

                //Valida o carimbo de tempo gerado
                timeStampGenerator.validateTimeStamp(content, response, hash);
            } else {
                throw new SignerException(xadesMessagesBundle.getString("error.tsa.not.found"));
            }
        } catch (SecurityException  ex) {
            throw new SignerException(ex.getMessage());
        }
		return response;
		
	}
    
    

}
