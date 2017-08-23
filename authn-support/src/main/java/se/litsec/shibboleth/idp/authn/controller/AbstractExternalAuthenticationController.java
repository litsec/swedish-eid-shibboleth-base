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
package se.litsec.shibboleth.idp.authn.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;

/**
 * Abstract base class for controllers implementing "external authentication".
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public abstract class AbstractExternalAuthenticationController {

  /** Logging instance. */
  private final Logger logger = LoggerFactory.getLogger(AbstractExternalAuthenticationController.class);

  /** Strategy used to locate the {@link AuthnRequest} to operate on. */
  @SuppressWarnings("rawtypes") private Function<ProfileRequestContext, AuthnRequest> requestLookupStrategy = Functions.compose(
    new MessageLookup<>(AuthnRequest.class), new InboundMessageContextLookup());

  /** Strategy used to locate the SP {@link EntityDescriptor} (metadata). */
  @SuppressWarnings("rawtypes") private Function<ProfileRequestContext, EntityDescriptor> peerMetadataLookupStrategy = Functions.compose(
    new PeerMetadataContextLookup(),
    Functions.compose(new SAMLPeerEntityContextLookup(), new InboundMessageContextLookup()));

  /**
   * Main entry point for the external authentication controller. The implementation starts a Shibboleth external
   * authentication process and hands over the control to
   * {@link #doExternalAuthentication(HttpServletRequest, HttpServletResponse, String, ProfileRequestContext)}.
   * 
   * @param httpRequest
   *          the HTTP request
   * @param httpResponse
   *          the HTTP response
   * @return a model and view object
   * @throws ExternalAuthenticationException
   *           for Shibboleth session errors
   */
  @RequestMapping("/extauth")
  public final ModelAndView processExternalAuthentication(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
      throws ExternalAuthenticationException {

    // Start the external authentication process ...
    //
    final String key = ExternalAuthentication.startExternalAuthentication(httpRequest);
    logger.debug("External authentication started. [key='{}',client-ip-address='{}']", key, httpRequest.getRemoteAddr());

    final ProfileRequestContext<?, ?> profileRequestContext = ExternalAuthentication.getProfileRequestContext(key, httpRequest);

    // Hand over to implementation ...
    //
    return this.doExternalAuthentication(httpRequest, httpResponse, key, profileRequestContext);
  }

  /**
   * Abstract method that must be implemented by subclasses in order to implement the authentication.
   * 
   * @param httpRequest
   *          the HTTP request
   * @param httpResponse
   *          the HTTP response
   * @param key
   *          the Shibboleth external authentication key
   * @param profileRequestContext
   *          the Shibboleth request context
   * @return a model and view object
   * @throws ExternalAuthenticationException
   *           for Shibboleth session errors
   */
  protected abstract ModelAndView doExternalAuthentication(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String key,
      ProfileRequestContext<?, ?> profileRequestContext) throws ExternalAuthenticationException;

  /**
   * Utility method that may be used to obtain the {@link AuthnRequest} message that initiated this authentication
   * process.
   * 
   * @param context
   *          the profile context
   * @return the authentication request message
   */
  protected AuthnRequest getAuthnRequest(ProfileRequestContext<?, ?> context) {
    return this.requestLookupStrategy.apply(context);
  }

  /**
   * Utility method that may be used to obtain the SAML metadata for the peer (i.e., the Service Provider) that sent the
   * authentication request.
   * 
   * @param context
   *          the profile context
   * @return the entity descriptor
   */
  protected EntityDescriptor getPeerMetadata(ProfileRequestContext<?, ?> context) {
    return this.peerMetadataLookupStrategy.apply(context);
  }

  /**
   * Lookup function for finding a {@link SAMLPeerEntityContext}.
   */
  @SuppressWarnings("rawtypes")
  public static class SAMLPeerEntityContextLookup implements ContextDataLookupFunction<MessageContext, SAMLPeerEntityContext> {

    @Override
    public SAMLPeerEntityContext apply(MessageContext input) {
      return input != null ? input.getSubcontext(SAMLPeerEntityContext.class, false) : null;
    }
  }

  /**
   * Lookup function for finding a {@link EntityDescriptor} in a {@code SAMLPeerEntityContext}.
   */
  public static class PeerMetadataContextLookup implements ContextDataLookupFunction<SAMLPeerEntityContext, EntityDescriptor> {

    @Override
    public EntityDescriptor apply(SAMLPeerEntityContext input) {

      if (input != null) {
        SAMLMetadataContext metadataContext = input.getSubcontext(SAMLMetadataContext.class, false);
        if (metadataContext != null) {
          return metadataContext.getEntityDescriptor();
        }
      }
      return null;
    }

  }

}
