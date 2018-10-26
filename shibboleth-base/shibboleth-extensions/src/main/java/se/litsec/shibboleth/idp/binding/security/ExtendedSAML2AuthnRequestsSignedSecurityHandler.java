/*
 * Copyright 2017-2018 Litsec AB
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
package se.litsec.shibboleth.idp.binding.security;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.binding.security.impl.SAML2AuthnRequestsSignedSecurityHandler;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extends the default {@link SAML2AuthnRequestsSignedSecurityHandler} implementation with an enforced check that
 * ensures that an {@code AuthnRequest} is signed if the IdP requires that, independently of the SP metadata.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class ExtendedSAML2AuthnRequestsSignedSecurityHandler extends SAML2AuthnRequestsSignedSecurityHandler {

  /** Logger. */
  private final Logger log = LoggerFactory.getLogger(ExtendedSAML2AuthnRequestsSignedSecurityHandler.class);

  /** Tells whether the IdP wants {@code AuthnRequest} messages signed. */
  private boolean wantAuthnRequestsSigned = false;

  /** {@inheritDoc} */
  @Override
  public void doInvoke(MessageContext<SAMLObject> messageContext) throws MessageHandlerException {
    if (this.wantAuthnRequestsSigned) {

      SAMLObject samlMessage = messageContext.getMessage();
      if (!(samlMessage instanceof AuthnRequest)) {
        log.debug("Inbound message is not an instance of AuthnRequest, skipping evaluation...");
        return;
      }
      if (!isMessageSigned(messageContext)) {
        log.error("AuthnRequest was not signed - this is required by the IdP");
        throw new MessageHandlerException("Inbound AuthnRequest was required to be signed but was not");
      }
    }
    else {
      super.doInvoke(messageContext);
    }
  }

  /**
   * Assigns whether the IdP requires authentication requests to be signed.
   * 
   * @param wantAuthnRequestsSigned
   *          does the IdP require requests to be signed
   */
  public void setWantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
    this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
  }

}
