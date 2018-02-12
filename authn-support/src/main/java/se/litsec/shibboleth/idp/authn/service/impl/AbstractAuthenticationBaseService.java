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
package se.litsec.shibboleth.idp.authn.service.impl;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import se.litsec.shibboleth.idp.authn.context.strategy.AuthenticationContextLookup;
import se.litsec.shibboleth.idp.authn.context.strategy.SAMLPeerEntityContextLookup;
import se.litsec.shibboleth.idp.authn.controller.AbstractExternalAuthenticationController.PeerMetadataContextLookup;
import se.litsec.shibboleth.idp.authn.service.AuthenticationBaseService;

/**
 * Abstract base class for services implementations.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public abstract class AbstractAuthenticationBaseService implements AuthenticationBaseService {

  /** Strategy that gives us the AuthenticationContext. */
  @SuppressWarnings("rawtypes") protected static Function<ProfileRequestContext, AuthenticationContext> authenticationContextLookupStrategy = 
      new AuthenticationContextLookup();

  /** Strategy used to locate the SP {@link EntityDescriptor} (metadata). */
  @SuppressWarnings("rawtypes") protected static Function<ProfileRequestContext, EntityDescriptor> peerMetadataLookupStrategy = 
      Functions.compose(new PeerMetadataContextLookup(), Functions.compose(new SAMLPeerEntityContextLookup(), new InboundMessageContextLookup()));

  /** Strategy used to locate the {@link AuthnRequest} to operate on. */
  @SuppressWarnings("rawtypes") protected static Function<ProfileRequestContext, AuthnRequest> requestLookupStrategy = 
      Functions.compose(new MessageLookup<>(AuthnRequest.class), new InboundMessageContextLookup());

  /**
   * Utility method that may be used to obtain the SAML metadata for the peer (i.e., the Service Provider) that sent the
   * authentication request.
   * 
   * @param context
   *          the profile context
   * @return the entity descriptor
   * @see #getPeerMetadata(HttpServletRequest)
   */
  protected EntityDescriptor getPeerMetadata(ProfileRequestContext<?, ?> context) {
    return peerMetadataLookupStrategy.apply(context);
  }

  /**
   * Utility method that may be used to obtain the {@link AuthnRequest} message that initiated this authentication
   * process.
   * 
   * @param context
   *          the profile context
   * @return the authentication request message
   */
  protected AuthnRequest getAuthnRequest(ProfileRequestContext<?, ?> context) {
    return requestLookupStrategy.apply(context);
  }

  /**
   * Returns a string to include in logging statements. The returned log string contains information about the current
   * request being processed. The format on the log string is {@code key1='value1',key2='value2', ...}.
   * 
   * @param context
   *          request context
   * @return a string to be used in log entries
   */
  protected String getLogString(ProfileRequestContext<?, ?> context) {
    try {
      AuthnRequest authnRequest = this.getAuthnRequest(context);
      return String.format("request-id='%s',sp='%s'", authnRequest.getID(), authnRequest.getIssuer().getValue());
    }
    catch (Exception e) {
      return "";
    }
  }

}
