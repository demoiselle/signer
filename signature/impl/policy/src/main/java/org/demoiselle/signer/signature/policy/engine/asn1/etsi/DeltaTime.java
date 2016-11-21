package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class DeltaTime extends ASN1Object {
	
	private Integer deltaSeconds;
	private Integer deltaMinutes;
	private Integer deltaHours;
	private Integer deltaDays;
	
	public Integer getDeltaSeconds() {
		return deltaSeconds;
	}
	public void setDeltaSeconds(Integer deltaSeconds) {
		this.deltaSeconds = deltaSeconds;
	}
	public Integer getDeltaMinutes() {
		return deltaMinutes;
	}
	public void setDeltaMinutes(Integer deltaMinutes) {
		this.deltaMinutes = deltaMinutes;
	}
	public Integer getDeltaHours() {
		return deltaHours;
	}
	public void setDeltaHours(Integer deltaHours) {
		this.deltaHours = deltaHours;
	}
	public Integer getDeltaDays() {
		return deltaDays;
	}
	public void setDeltaDays(Integer deltaDays) {
		this.deltaDays = deltaDays;
	}	

}
