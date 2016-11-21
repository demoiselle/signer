/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.demoiselle.signer.signature.signer.pkcs7.attribute.impl;

import org.demoiselle.signer.signature.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.signature.signer.SignerException;
import org.demoiselle.signer.signature.signer.pkcs7.attribute.UnsignedAttribute;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.bouncycastle.asn1.cms.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class CertValues implements UnsignedAttribute {

    private static final Logger logger = LoggerFactory.getLogger(CertValues.class);
    private final String identifier = "1.2.840.113549.1.9.16.2.23";

    @Override
    public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy) {

    }

    @Override
    public String getOID() {
        return identifier;
    }

    @Override
    public Attribute getValue() throws SignerException {
        throw new UnsupportedOperationException("Ainda não há suporte.");
    }

}
