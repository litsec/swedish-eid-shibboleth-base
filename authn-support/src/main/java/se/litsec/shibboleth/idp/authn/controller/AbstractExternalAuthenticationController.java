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

import java.io.IOException;
import java.util.Arrays;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.joda.time.DateTime;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import se.litsec.shibboleth.idp.attribute.resolver.SAML2AttributeNameToIdMapperService;
import se.litsec.shibboleth.idp.authn.ExtAuthnEventIds;
import se.litsec.shibboleth.idp.authn.IdpErrorStatusException;
import se.litsec.shibboleth.idp.context.ProxiedStatusContext;
import se.litsec.swedisheid.opensaml.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.litsec.swedisheid.opensaml.saml2.metadata.entitycategory.EntityCategoryMetadataHelper;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessage;

/**
 * Abstract base class for controllers implementing "external authentication".
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public abstract class AbstractExternalAuthenticationController implements InitializingBean {

  /** The name for the session attribute where we store the external authentication key. */
  public static final String EXTAUTHN_KEY_ATTRIBUTE_NAME = "se.litsec.shibboleth.idp.authn.ExternalAuthnKey";

  /** Logging instance. */
  private final Logger logger = LoggerFactory.getLogger(AbstractExternalAuthenticationController.class);

  /** Helper that maps from SAML 2 attribute names to their corresponding Shibboleth attribute id:s. */
  private SAML2AttributeNameToIdMapperService attributeToIdMapping;

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
   * @throws IOException
   *           for IO errors
   */
  @RequestMapping("/extauth")
  public final ModelAndView processExternalAuthentication(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
      throws ExternalAuthenticationException, IOException {

    // Start the external authentication process ...
    //
    final String key = ExternalAuthentication.startExternalAuthentication(httpRequest);
    logger.debug("External authentication started. [key='{}',client-ip-address='{}']", key, httpRequest.getRemoteAddr());

    final ProfileRequestContext<?, ?> profileRequestContext = ExternalAuthentication.getProfileRequestContext(key, httpRequest);

    // Store the authentication key in the HTTP session.
    //
    HttpSession session = httpRequest.getSession();
    session.setAttribute(EXTAUTHN_KEY_ATTRIBUTE_NAME, key);

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
   * @throws IOException
   *           for IO errors
   */
  protected abstract ModelAndView doExternalAuthentication(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String key,
      ProfileRequestContext<?, ?> profileRequestContext) throws ExternalAuthenticationException, IOException;

  /**
   * Returns the name that this authenticator has. Mainly used for logging.
   * 
   * @return the authenticator name
   */
  public abstract String getAuthenticatorName();

  /**
   * Returns the Shibboleth external authentication key for the current session.
   * 
   * @param httpRequest
   *          the HTTP request
   * @return the Shibboleth external authentication key
   * @throws ExternalAuthenticationException
   *           if no active session exists
   */
  protected String getExternalAuthenticationKey(HttpServletRequest httpRequest) throws ExternalAuthenticationException {
    String key = (String) httpRequest.getSession().getAttribute(EXTAUTHN_KEY_ATTRIBUTE_NAME);
    if (key == null) {
      throw new ExternalAuthenticationException("No external authentication process is active");
    }
    return key;
  }

  /**
   * Returns the {@link ProfileRequestContext} object associated with the current authentication process.
   * 
   * @param httpRequest
   *          the HTTP request
   * @return the context
   * @throws ExternalAuthenticationException
   *           if no active session exists
   */
  protected ProfileRequestContext<?, ?> getProfileRequestContext(HttpServletRequest httpRequest) throws ExternalAuthenticationException {
    return ExternalAuthentication.getProfileRequestContext(this.getExternalAuthenticationKey(httpRequest), httpRequest);
  }

  /**
   * Method that should be invoked to exit the external authentication process with a successful result.
   * 
   * @param httpRequest
   *          the HTTP request
   * @param httpResponse
   *          the HTTP response
   * @param subject
   *          the subject of the authenticated user (contains the attributes of the user)
   * @param authnInstant
   *          the authentication instant - if {@code null} the current time will be used
   * @param cacheForSSO
   *          should the result be cached for later SSO? If {@code null}, the result will be cached
   * @throws ExternalAuthenticationException
   *           for Shibboleth session errors
   * @throws IOException
   *           for IO errors
   */
  protected void success(HttpServletRequest httpRequest, HttpServletResponse httpResponse, Subject subject,
      DateTime authnInstant, Boolean cacheForSSO) throws ExternalAuthenticationException, IOException {

    final String key = this.getExternalAuthenticationKey(httpRequest);

    // Assign the authenticated subject.
    httpRequest.setAttribute(ExternalAuthentication.SUBJECT_KEY, subject);

    // Assign the authentication instant.
    if (authnInstant == null) {
      authnInstant = new DateTime();
    }
    httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_INSTANT_KEY, authnInstant);

    // Tell Shibboleth processing whether this result should be cached for SSO or not.
    httpRequest.setAttribute(ExternalAuthentication.DONOTCACHE_KEY, cacheForSSO == null ? Boolean.FALSE : !cacheForSSO);

    // Finish the external authentication task and return to the flow.
    ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
    httpRequest.getSession().removeAttribute(EXTAUTHN_KEY_ATTRIBUTE_NAME);
  }

  /**
   * Method that should be invoked before exiting the external authentication process and indicate that the user
   * cancelled the authentication.
   * 
   * @param httpRequest
   *          the HTTP request
   * @param httpResponse
   *          the HTTP response
   * @throws ExternalAuthenticationException
   *           for Shibboleth session errors
   * @throws IOException
   *           for IO errors
   */
  protected void cancel(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
      throws ExternalAuthenticationException, IOException {
    this.error(httpRequest, httpResponse, ExtAuthnEventIds.CANCEL_AUTHN);
  }

  /**
   * Method that should be invoked to exit the external authentication process with an error.
   * 
   * @param httpRequest
   *          the HTTP request
   * @param httpResponse
   *          the HTTP response
   * @param authnEventId
   *          the Shibboleth event ID to signal
   * @throws ExternalAuthenticationException
   *           for Shibboleth session errors
   * @throws IOException
   *           for IO errors
   * @see #error(HttpServletRequest, HttpServletResponse, Exception)
   * @see #error(HttpServletRequest, HttpServletResponse, Status)
   */
  protected void error(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String authnEventId)
      throws ExternalAuthenticationException, IOException {

    final String key = this.getExternalAuthenticationKey(httpRequest);
    httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, authnEventId);
    ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
    httpRequest.getSession().removeAttribute(EXTAUTHN_KEY_ATTRIBUTE_NAME);
  }

  /**
   * Method that should be invoked to exit the external authentication process with an error.
   * 
   * @param httpRequest
   *          the HTTP request
   * @param httpResponse
   *          the HTTP response
   * @param error
   *          the error exception
   * @throws ExternalAuthenticationException
   *           for Shibboleth session errors
   * @throws IOException
   *           for IO errors
   * @see #error(HttpServletRequest, HttpServletResponse, String)
   * @see #error(HttpServletRequest, HttpServletResponse, Status)
   */
  protected void error(HttpServletRequest httpRequest, HttpServletResponse httpResponse, Exception error)
      throws ExternalAuthenticationException, IOException {

    final String key = this.getExternalAuthenticationKey(httpRequest);

    if (error instanceof IdpErrorStatusException) {
      Status s = ((IdpErrorStatusException) error).getStatus();
      if (s.getStatusCode() == null || StatusCode.SUCCESS.equals(s.getStatusCode().getValue())) {
        throw new IllegalArgumentException("Bad call to error - Status is successful");
      }
      ProfileRequestContext<?, ?> profileRequestContext = this.getProfileRequestContext(httpRequest);
      profileRequestContext.addSubcontext(new ProxiedStatusContext(s), true);
    }

    httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_EXCEPTION_KEY, error);
    ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
    httpRequest.getSession().removeAttribute(EXTAUTHN_KEY_ATTRIBUTE_NAME);
  }

  /**
   * Method that should be invoked to exit the external authentication process with an error where the SAML status to
   * respond with is given.
   * 
   * @param httpRequest
   *          the HTTP request
   * @param httpResponse
   *          the HTTP response
   * @param errorStatus
   *          the SAML status
   * @throws ExternalAuthenticationException
   *           for Shibboleth session errors
   * @throws IOException
   *           for IO errors
   * @see #error(HttpServletRequest, HttpServletResponse, String)
   * @see #error(HttpServletRequest, HttpServletResponse, Exception)
   */
  protected void error(HttpServletRequest httpRequest, HttpServletResponse httpResponse, Status errorStatus)
      throws ExternalAuthenticationException, IOException {
    this.error(httpRequest, httpResponse, new IdpErrorStatusException(errorStatus));
  }

  /**
   * Utility method that may be used to obtain the {@link AuthnRequest} message that initiated this authentication
   * process.
   * 
   * @param context
   *          the profile context
   * @return the authentication request message
   * @see #getAuthnRequest(HttpServletRequest)
   */
  protected AuthnRequest getAuthnRequest(ProfileRequestContext<?, ?> context) {
    return this.requestLookupStrategy.apply(context);
  }

  /**
   * See {@link #getAuthnRequest(ProfileRequestContext)}.
   * 
   * @param httpRequest
   *          the HTTP request
   * @return the authentication request message
   * @throws ExternalAuthenticationException
   *           for Shibboleth session errors
   */
  protected AuthnRequest getAuthnRequest(HttpServletRequest httpRequest) throws ExternalAuthenticationException {
    return this.getAuthnRequest(this.getProfileRequestContext(httpRequest));
  }

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
    return this.peerMetadataLookupStrategy.apply(context);
  }

  /**
   * See {@link #getPeerMetadata(ProfileRequestContext)}.
   * 
   * @param httpRequest
   *          The HTTP request
   * @return the entity descriptor
   * @throws ExternalAuthenticationException
   *           for Shibboleth session errors
   */
  protected EntityDescriptor getPeerMetadata(HttpServletRequest httpRequest) throws ExternalAuthenticationException {
    return this.getPeerMetadata(this.getProfileRequestContext(httpRequest));
  }

  /**
   * Utility method that finds out whether the request that we are processing was sent by a "signature service".
   * 
   * @param context
   *          the profile context
   * @return if the peer is a signature service {@code true} is returned, otherwise {@code false}
   * @see #isSignatureServicePeer(HttpServletRequest)
   */
  protected boolean isSignatureServicePeer(ProfileRequestContext<?, ?> context) {
    EntityDescriptor peerMetadata = this.getPeerMetadata(context);
    if (peerMetadata == null) {
      logger.error("No metadata available for connecting SP");
      return false;
    }
    return EntityCategoryMetadataHelper.getEntityCategories(peerMetadata)
      .stream()
      .filter(c -> EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri().equals(c))
      .findFirst()
      .isPresent();
  }

  /**
   * See {@link #isSignatureServicePeer(ProfileRequestContext)}.
   * 
   * @param httpRequest
   *          The HTTP request
   * @return if the peer is a signature service {@code true} is returned, otherwise {@code false}
   * @throws ExternalAuthenticationException
   *           for Shibboleth session errors
   */
  protected boolean isSignatureServicePeer(HttpServletRequest httpRequest) throws ExternalAuthenticationException {
    return this.isSignatureServicePeer(this.getProfileRequestContext(httpRequest));
  }

  /**
   * If the IdP was called by a signature service ({@link #isSignatureServicePeer(ProfileRequestContext)} returns
   * {@code true}), the {@code AuthnRequest} should contain a {@code SignMessage} element extension. This method returns
   * this object.
   * 
   * @param context
   *          the profile context
   * @return a {@code SignMessage} or {@code null} if none is available
   */
  protected SignMessage getSignMessage(ProfileRequestContext<?, ?> context) {
    AuthnRequest authnRequest = this.getAuthnRequest(context);
    if (authnRequest == null) {
      logger.error("No AuthnRequest is available");
      return null;
    }
    if (authnRequest.getExtensions() == null) {
      return null;
    }
    return authnRequest.getExtensions()
      .getUnknownXMLObjects()
      .stream()
      .filter(SignMessage.class::isInstance)
      .map(SignMessage.class::cast)
      .findFirst()
      .orElse(null);
  }

  /**
   * See {@link #getSignMessage(ProfileRequestContext)}.
   * 
   * @param httpRequest
   *          the HTTP request
   * @return a {@code SignMessage} or {@code null} if none is available
   * @throws ExternalAuthenticationException
   *           for Shibboleth session errors
   */
  protected SignMessage getSignMessage(HttpServletRequest httpRequest) throws ExternalAuthenticationException {
    return this.getSignMessage(this.getProfileRequestContext(httpRequest));
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
   * Adds the service that provides mappings from SAML 2 attribute names to their corresponding Shibboleth attribute
   * id:s.
   * 
   * @param attributeToIdMapping
   *          mapper service
   */
  public void setAttributeToIdMapping(SAML2AttributeNameToIdMapperService attributeToIdMapping) {
    this.attributeToIdMapping = attributeToIdMapping;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.attributeToIdMapping, "Property 'attributeToIdMapping' must be assigned");
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

  protected SubjectBuilder getSubjectBuilder(String principal) {
    return new SubjectBuilder(principal, this.attributeToIdMapping);
  }

  protected static class SubjectBuilder {

    private Subject subject;

    private SAML2AttributeNameToIdMapperService attributeToIdMapping;

    private SubjectBuilder(String principal, SAML2AttributeNameToIdMapperService attributeToIdMapping) {
      this.attributeToIdMapping = attributeToIdMapping;
      this.subject = new Subject();
      subject.getPrincipals().add(new UsernamePrincipal(principal));
    }

    public Subject build() {
      return this.subject;
    }

    public SubjectBuilder shibbolethAttribute(String attributeId, String value) {
      if (value == null) {
        return this;
      }
      IdPAttribute attr = new IdPAttribute(attributeId);
      attr.setValues(Arrays.asList(new StringAttributeValue(value)));
      this.subject.getPrincipals().add(new IdPAttributePrincipal(attr));
      return this;
    }

    public SubjectBuilder attribute(String name, String value) {
      String attributeId = this.attributeToIdMapping.getAttributeID(name);
      if (attributeId == null) {
        // TODO: throw
        return this;
      }
      return this.shibbolethAttribute(attributeId, value);
    }

    public SubjectBuilder authnContextClassRef(String uri) {
      this.subject.getPrincipals().add(new AuthnContextClassRefPrincipal(uri));
      return this;
    }
  }

}
