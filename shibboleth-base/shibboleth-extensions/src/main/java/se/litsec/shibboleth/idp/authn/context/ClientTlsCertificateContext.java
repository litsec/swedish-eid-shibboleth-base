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

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.BaseContext;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A context in where we save a client TLS certificate. This is used when implementing the Holder-of-key WebSSO profile.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class ClientTlsCertificateContext extends BaseContext {

  /** Class logger. */
  private final Logger log = LoggerFactory.getLogger(ClientTlsCertificateContext.class);

  /** The client certificate. */
  private final X509Certificate clientCertificate;

  /**
   * Setting that tells whether the entire certificate, or just a ds:KeyValue should be included in the
   * SubjectConfirmation.
   */
  private boolean includeOnlyKey = false;

  /**
   * Constructor.
   * 
   * @param clientCertificate
   *          the client certificate
   */
  public ClientTlsCertificateContext(final X509Certificate clientCertificate) {
    this.clientCertificate = clientCertificate;
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
   * Gets the object that should be included in a SubjectConfirmation element.
   * 
   * @return the object to include
   *
   */
  public KeyInfo getObjectForSubjectConfirmation() {

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
