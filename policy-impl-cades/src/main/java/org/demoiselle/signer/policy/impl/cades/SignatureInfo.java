package org.demoiselle.signer.policy.impl.cades;

import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.TimeZone;

import org.demoiselle.signer.timestamp.Timestamp;

/**
 * Basic informations about a signature 
 * 
 *
 */
public class SignatureInfo {
	
	public LinkedList<X509Certificate> chain;
	public Date signDate;
    public Timestamp timeStampSigner = null;


    /**
     * 
     * @return list of Certificate chain stored on signature
     */
	public LinkedList<X509Certificate> getChain() {
		return chain;
	}

	public void setChain(LinkedList<X509Certificate> chain) {
		this.chain = chain;
	}

	/**
	 * 
	 * @return Date when signature was generated (it is NOT a timestamp date) 
	 *
	 */
	public Date getSignDate() {
		return signDate;
	}

	/**
	 * 
	 * @return String DateGMT when signature was generated (it is NOT a timestamp date) 
	 *
	 */
	public String getSignDateGMT() {
        SimpleDateFormat dateFormatGmt = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss:S z");
        dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
        return dateFormatGmt.format(this.getSignDate());
    }
	
	
	public void setSignDate(Date signDate) {
		this.signDate = signDate;
	}

	/**
	 * 
	 * @return TimeStamp stored on signature
	 */
	public Timestamp getTimeStampSigner() {
		return timeStampSigner;
	}

	public void setTimeStampSigner(Timestamp timeStampSigner) {
		this.timeStampSigner = timeStampSigner;
	}
	
	
	
}