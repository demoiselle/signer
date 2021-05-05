package org.demoiselle.signer.policy.impl.pades.pkcs7;

import java.security.cert.Certificate;

import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.Signer;

public interface PCKS7Signer extends Signer {
	
	/**
	 *  Assign a Certificate for validate or generate a signature
	 * @param certificate certificate to be used
	 */
    abstract public void setCertificates(Certificate certificate[]);

    /**
     * Assign a Policy for validate or generate a signature 
     * @param signaturePolicy Signature policy to be used
     */
    abstract public void setSignaturePolicy(Policies signaturePolicy);
    
    
    /**
	 *  Assign a Certificate for get timeStamp
	 * @param certificate certificate to be used
	 */
    abstract public void setCertificatesForTimeStamp(Certificate certificates[]);
    

}
