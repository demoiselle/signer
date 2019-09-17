package org.demoiselle.signer.policy.impl.pades.pkcs7;

import java.util.List;

import org.demoiselle.signer.policy.impl.cades.Checker;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;

public interface PKCS7Checker extends Checker{ 
	
    /**
     * get Signature Information for a checked signature
     * @return List&lt;SignatureInformations&gt;
     */
    abstract public List<SignatureInformations> getSignaturesInfo();


}
