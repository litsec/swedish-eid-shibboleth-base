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

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import se.litsec.shibboleth.idp.authn.ExternalAutenticationErrorCodeException;
import se.litsec.shibboleth.idp.authn.context.AuthnContextClassContext;
import se.litsec.shibboleth.idp.authn.context.strategy.AuthenticationContextLookup;
import se.litsec.shibboleth.idp.authn.context.strategy.AuthnContextClassContextLookup;
import se.litsec.shibboleth.idp.authn.context.strategy.RequestedPrincipalContextLookup;
import se.litsec.shibboleth.idp.authn.service.AuthnContextService;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI.LoaEnum;

/**
 * Implementation of {@link AuthnContextService}.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class AuthnContextServiceImpl extends AbstractAuthenticationBaseService implements AuthnContextService,
    InitializingBean {

  /** Logging instance. */
  private final Logger log = LoggerFactory.getLogger(AuthnContextServiceImpl.class);

  /**
   * The Shibboleth bean shibboleth.AuthenticationPrincipalWeightMap. We use this to find out the default Authentication
   * Context URI to use.
   */
  protected Map<Principal, Integer> authnContextweightMap;

  /** The name of the Shibboleth flow that this authentication method uses. */
  protected String flowName;

  /** Strategy that gives us the AuthenticationContext. */
  @SuppressWarnings("rawtypes") protected Function<ProfileRequestContext, AuthenticationContext> authenticationContextLookupStrategy = new AuthenticationContextLookup();

  /** Strategy used to locate the requested principal context. */
  @SuppressWarnings("rawtypes") protected Function<ProfileRequestContext, RequestedPrincipalContext> requestedPrincipalLookupStrategy = Functions
    .compose(new RequestedPrincipalContextLookup(), this.authenticationContextLookupStrategy);

  /** Strategy used to locate the AuthnContextClassContext. */
  @SuppressWarnings("rawtypes") protected Function<ProfileRequestContext, AuthnContextClassContext> authnContextClassLookupStrategy = Functions
    .compose(new AuthnContextClassContextLookup(), this.authenticationContextLookupStrategy);

  /** {@inheritDoc} */
  @Override
  public void initializeContext(ProfileRequestContext<?, ?> context) throws ExternalAutenticationErrorCodeException {
    final String logId = this.getLogString(context);

    AuthenticationContext authenticationContext = this.authenticationContextLookupStrategy.apply(context);
    if (authenticationContext == null) {
      log.error("No AuthenticationContext available [{}]", logId);
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.INVALID_AUTHN_CTX, "No AuthenticationContext available");
    }

    RequestedPrincipalContext requestedPrincipalContext = this.requestedPrincipalLookupStrategy.apply(context);
    List<String> requstedPrincipals;
    if (requestedPrincipalContext == null) {
      log.info("No RequestedPrincipalContext available - no AuthnContextClassRefs in AuthnRequest [{}]", logId);
      requstedPrincipals = Collections.emptyList();
    }
    else {
      requstedPrincipals = requestedPrincipalContext.getRequestedPrincipals()
        .stream()
        .filter(AuthnContextClassRefPrincipal.class::isInstance)
        .map(Principal::getName)
        .collect(Collectors.toList());
    }

    log.debug("Initializing RequestedAuthnContextClassContext with AuthnContextClassRef URI:s: {} [{}]", requestedPrincipalContext, logId);
    authenticationContext.addSubcontext(new AuthnContextClassContext(requstedPrincipals), true);
  }

  /** {@inheritDoc} */
  @Override
  public AuthnContextClassContext getAuthnContextClassContext(ProfileRequestContext<?, ?> context)
      throws ExternalAutenticationErrorCodeException {
    AuthnContextClassContext authnContextClassContext = this.authnContextClassLookupStrategy.apply(context);
    if (authnContextClassContext == null) {
      if (authnContextClassContext == null) {
        log.error("No AuthnContextClassContext available [{}]", this.getLogString(context));
        throw new ExternalAutenticationErrorCodeException(AuthnEventIds.INVALID_AUTHN_CTX, "Missing AuthnContextClassContext");
      }
    }
    return authnContextClassContext;
  }

  /**
   * Processes the requested AuthnContextClass URI:s and verifies that they are valid regarding the type of request and
   * what is supported by the authentication method. The method may update the current context, for example filter out
   * URI:s that does not match the current authentication method.
   */
  @Override
  public void processRequest(ProfileRequestContext<?, ?> context) throws ExternalAutenticationErrorCodeException {

    final String logId = this.getLogString(context);

    AuthnContextClassContext authnContextContext = this.getAuthnContextClassContext(context);

    // If no URI is specified in the request, we add the IdP default choice(s)
    //
    if (authnContextContext.isEmpty()) {
      List<String> defaultUris = this.getDefaultAuthnContextClassRefs(context);
      log.info("No AuthnContext URI:s given in AuthnRequest - using IdP default(s): {} [{}]", defaultUris, logId);

      // Replace current context with new one.
      this.authenticationContextLookupStrategy.apply(context).addSubcontext(new AuthnContextClassContext(defaultUris), true);

    }
    // Else, make checks and remove URI:s that are not relevant.
    else {

      // First filter away those URI:s not supported by this authentication method.
      //
      final List<String> supportedUris = this.getSupportedAuthnContextClassRefs(context);
      for (String uri : authnContextContext.getAuthnContextClassRefs()) {
        if (!supportedUris.contains(uri)) {
          log.info("Requested AuthnContext URI '{}' is not supported by the current authentication method ({}), ignoring [{}]", uri,
            this.flowName, logId);
          authnContextContext.deleteAuthnContextClassRef(uri);
        }
      }

      // Now, if we don't have any URI:s left there is an error. The SP specified URI:s, but they were not accepted.
      //
      if (authnContextContext.isEmpty()) {
        final String msg = "No valid AuthnContext URI:s were specified in AuthnRequest";
        log.info("{} - can not proceed [{}]", msg, logId);
        throw new ExternalAutenticationErrorCodeException(AuthnEventIds.REQUEST_UNSUPPORTED, msg);
      }
    }

    // TODO: Move these to SignatureMessageService!

    // Make additional checks regarding the use of AuthnContext URI:s by signature services, and
    // make sure they are compliant with the Swedish eID deployment profile.
    //
    // boolean isSignatureService = signatureMessageService.isSignatureServicePeer(context);
    //
    // if (!isSignatureService && !authnContextContext.getSigMessageAuthnContextClassRefs().isEmpty()) {
    // // It is not valid to include a "sigmessage" URI in a request if you are not a "Signature Service",
    // // but we can safely filter those out.
    // log.info("AuthnRequest contains sigmessage AuthnContext URI(s) ({}), but SP is not a signature service, ignoring
    // [{}]'",
    // authnContextContext.getSigMessageAuthnContextClassRefs(), logId);
    // authnContextContext.getSigMessageAuthnContextClassRefs().stream().forEach(authnContextContext::deleteAuthnContextClassRef);
    // }

  }

  /** {@inheritDoc} */
  @Override
  public List<String> getSupportedAuthnContextClassRefs(ProfileRequestContext<?, ?> context) {
    AuthenticationContext authenticationContext = this.authenticationContextLookupStrategy.apply(context);
    if (authenticationContext == null) {
      log.error("No AuthenticationContext available");
      return Collections.emptyList();
    }
    AuthenticationFlowDescriptor authenticationFlowDescriptor = authenticationContext.getAvailableFlows().get(this.flowName);
    if (authenticationFlowDescriptor == null) {
      log.error("No authentication flow descriptor exists for {}", this.flowName);
      return Collections.emptyList();
    }
    List<String> uris = authenticationFlowDescriptor.getSupportedPrincipals()
      .stream()
      .filter(AuthnContextClassRefPrincipal.class::isInstance)
      .map(Principal::getName)
      .collect(Collectors.toList());

    log.debug("Supported AuthnContextClassRef URI:s by flow '{}': {}", this.flowName, uris);
    return uris;
  }

  /**
   * This implementation returns one element that is the IdP preferred choice.
   */
  @Override
  public List<String> getDefaultAuthnContextClassRefs(ProfileRequestContext<?, ?> context) {

    String uri = this.authnContextweightMap.entrySet()
      .stream()
      .sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
      .map(Map.Entry::getKey)
      .filter(AuthnContextClassRefPrincipal.class::isInstance)
      .map(Principal::getName)
      .findFirst()
      .orElse(null);

    if (uri == null) {
      log.error("No default AuthnContext URI defined in Shibboleth for flow '{}'", this.flowName);
    }
    return Arrays.asList(uri);
  }

  /**
   * Predicate that tells if the supplied URI is a URI indicating sign message display.
   * 
   * @param uri
   *          the URI to test
   * @return {@code true} if the supplied URI is for sign message, and {@code false} otherwise
   */
  protected boolean isSignMessageURI(String uri) {
    LoaEnum loa = LoaEnum.parse(uri);
    return (loa != null && loa.isSignatureMessageUri());
  }

  /**
   * Given a base URI, the method returns its corresponding sigmessage URI.
   * 
   * @param uri
   *          the URI to transform
   * @return the sigmessage URI, or {@code null} if no such exists
   */
  protected String toSignMessageURI(String uri) {
    LoaEnum loa = LoaEnum.parse(uri);
    if (loa == null) {
      return null;
    }
    if (loa.isSignatureMessageUri()) {
      return uri;
    }
    for (LoaEnum l : LoaEnum.values()) {
      if (l.getBaseUri().equals(loa.getBaseUri()) && l.isSignatureMessageUri() && l.isNotified() == loa.isNotified()) {
        return l.getUri();
      }
    }
    return null;
  }

  /**
   * Given an URI its base form is returned. This means that the URI minus any potential sigmessage extension.
   * 
   * @param uri
   *          the URI to convert
   * @return the base URI
   */
  protected String toBaseURI(String uri) {
    LoaEnum loa = LoaEnum.parse(uri);
    if (loa != null && loa.isSignatureMessageUri()) {
      return LoaEnum.minusSigMessage(loa).getUri();
    }
    return uri;
  }

  /**
   * The Shibboleth bean {@code shibboleth.AuthenticationPrincipalWeightMap}. We use this to find out the default
   * Authentication Context URI to use.
   * 
   * @param authnContextweightMap
   *          the Shibboleth bean {@code shibboleth.AuthenticationPrincipalWeightMap}
   */
  public void setAuthnContextweightMap(Map<Principal, Integer> authnContextweightMap) {
    this.authnContextweightMap = authnContextweightMap;
  }

  /**
   * Assigns the flow name for the authentication flow that this authentication method uses, e.g. "authn/External".
   * 
   * @param flowName
   *          the flow name
   */
  public void setFlowName(String flowName) {
    this.flowName = flowName;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notEmpty(this.authnContextweightMap, "Property 'authnContextweightMap' has not be assigned, or is empty");
    Assert.notNull(this.flowName, "Property 'flowName' must be assigned");
  }

}
