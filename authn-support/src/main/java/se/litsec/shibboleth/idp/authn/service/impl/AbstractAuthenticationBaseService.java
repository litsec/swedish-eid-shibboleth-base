/*
 * The swedish-eid-shibboleth-base is an open-source package that provides
 * an easy-to-use re-packaging of the Shibboleth Identity Provider for use
 * with the Swedish eID Framework. 
 *
 * More details on <https://github.com/litsec/swedish-eid-shibboleth-base> 
 * Copyright (C) 2017 Litsec AB
 * 
 * This program is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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
