/*
 * Copyright 2017-2022 Litsec AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.litsec.shibboleth.idp.authn.context;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.BaseContext;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.signature.KeyInfo;

/**
 * A context for handling the Holder-of-key profile.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class HolderOfKeyContext extends BaseContext {

  /** URI identifier for the Holder-of-key profile URI. */
  public static final String HOK_WEBSSO_PROFILE_URI = "urn:oasis:names:tc:SAML:2.0:profiles:holder-of-key:SSO:browser";

  /** The QName for the HoK ProtocolBinding attribute. */
  public static final QName HOK_PROTOCOL_BINDING_ATTRIBUTE = new QName(HOK_WEBSSO_PROFILE_URI, "ProtocolBinding", "hoksso");

  /** The client certificate. */
  private X509Certificate clientCertificate;

  /** A flag that tells whether the client certificate has been read (i.e., if we have tried to find the cert). */
  private boolean clientCertificateRead = false;

  /**
   * Setting that tells whether the entire certificate, or just a ds:KeyValue should be included in the
   * SubjectConfirmation.
   */
  private boolean includeOnlyKey = false;

  /** The client ACS that is active. */
  private AssertionConsumerService assertionConsumerService;

  /**
   * Since we want to cover for the special case when an AuthnRequest contains an AssertionConsumerServiceURL attribute
   * and the SP has defined two AssertionConsumerService elements with the same URL; one for plain WebSSO and one for
   * HoK, we set this flag if only one URL matches.
   */
  private boolean acsDefinite = true;
  
  /** Whether we should issue a HoK assertion (if there is a cert). */
  private boolean issueHokAssertion = true;

  /**
   * Constructor.
   */
  public HolderOfKeyContext() {
  }

  /**
   * Gets the client certificate.
   * 
   * @return the client certificate
   */
  public X509Certificate getClientCertificate() {
    return this.clientCertificate;
  }

  /**
   * Sets the client certificate.
   * 
   * @param clientCertificate
   *          the client certificate
   */
  public void setClientCertificate(final X509Certificate clientCertificate) {
    this.clientCertificate = clientCertificate;
  }

  /**
   * Tells whether we have attempted to read the client certificate.
   * 
   * @return whether we have attempted to read the client certificate
   */
  public boolean isClientCertificateRead() {
    return this.clientCertificateRead;
  }

  /**
   * Assigns whether we have attempted to read the client certificate.
   * 
   * @param clientCertificateRead
   *          whether the cert has been read
   */
  public void setClientCertificateRead(final boolean clientCertificateRead) {
    this.clientCertificateRead = clientCertificateRead;
  }

  /**
   * Setting that tells whether the entire certificate, or just a ds:KeyValue should be included in the
   * SubjectConfirmation.
   * 
   * @param includeOnlyKey
   *          whether only the key should be included
   */
  public void setIncludeOnlyKey(final boolean includeOnlyKey) {
    this.includeOnlyKey = includeOnlyKey;
  }

  /**
   * Gets the AssertionConsumerService element that matched this request.
   * 
   * @return the AssertionConsumerService element that matched this request
   */
  public AssertionConsumerService getAssertionConsumerService() {
    return this.assertionConsumerService;
  }

  /**
   * Assigns the AssertionConsumerService element that matched this request.
   * 
   * @param assertionConsumerService
   *          the AssertionConsumerService element that matched this request
   */
  public void setAssertionConsumerService(final AssertionConsumerService assertionConsumerService) {
    this.assertionConsumerService = assertionConsumerService;
  }

  /**
   * Predicate that tells if the stored ACS is intended for Holder-of-key.
   * 
   * @return true if it is a HoK ACS and false otherwise
   */
  public boolean isHokAssertionConsumerService() {
    if (this.assertionConsumerService == null) {
      return false;
    }
    return HOK_WEBSSO_PROFILE_URI.equals(this.assertionConsumerService.getBinding());
  }

  /**
   * Since we want to cover for the special case when an AuthnRequest contains an AssertionConsumerServiceURL attribute
   * and the SP has defined two AssertionConsumerService elements with the same URL; one for plain WebSSO and one for
   * HoK, we set this flag if only one URL matches.
   * 
   * @return true if we are sure about the use for the ACS.
   */
  public boolean isAcsDefinite() {
    return this.acsDefinite;
  }

  /**
   * Since we want to cover for the special case when an AuthnRequest contains an AssertionConsumerServiceURL attribute
   * and the SP has defined two AssertionConsumerService elements with the same URL; one for plain WebSSO and one for
   * HoK, we set this flag if only one URL matches.
   * 
   * @param acsDefinite
   *          true if we are sure about the use for the ACS
   */
  public void setAcsDefinite(final boolean acsDefinite) {
    this.acsDefinite = acsDefinite;
  }
  
  public boolean isIssueHokAssertion() {
    return this.issueHokAssertion && this.clientCertificate != null;
  }
  
  public void setIssueHokAssertion(final boolean issueHokAssertion) {
    this.issueHokAssertion = issueHokAssertion;
  }

  /**
   * Gets the object that should be included in a SubjectConfirmation element.
   * 
   * @return the object to include
   *
   */
  public KeyInfo getObjectForSubjectConfirmation() {

    if (this.clientCertificate == null) {
      return null;
    }

    final KeyInfo keyInfo = KeyInfo.class.cast(XMLObjectSupport.buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME));

    if (this.includeOnlyKey && !(this.clientCertificate.getPublicKey() instanceof ECPublicKey)) {
      // EC keys is not supported by OpenSAML 3!
      KeyInfoSupport.addPublicKey(keyInfo, this.clientCertificate.getPublicKey());
    }
    else {
      try {
        KeyInfoSupport.addCertificate(keyInfo, this.clientCertificate);
      }
      catch (final CertificateEncodingException e) {
        throw new SecurityException(e);
      }
    }
    return keyInfo;
  }

}
