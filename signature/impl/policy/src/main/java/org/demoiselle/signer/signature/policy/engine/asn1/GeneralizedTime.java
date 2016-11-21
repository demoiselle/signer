package org.demoiselle.signer.signature.policy.engine.asn1;

import java.text.ParseException;
import java.util.Date;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Primitive;

public class GeneralizedTime extends ASN1Object {

    private Date date;

    @Override
    public void parse(ASN1Primitive derObject) {
        if (derObject instanceof ASN1GeneralizedTime) {
            ASN1GeneralizedTime derGeneralizedTime = (ASN1GeneralizedTime) derObject;
            try {
                this.setDate(derGeneralizedTime.getDate());
            } catch (ParseException error) {
                throw new RuntimeException(error);
            }
        }
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

}
