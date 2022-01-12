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
package se.litsec.shibboleth.idp.authn.service.impl;

import java.security.Principal;
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
import se.litsec.shibboleth.idp.authn.context.strategy.AuthnContextClassContextLookup;
import se.litsec.shibboleth.idp.authn.context.strategy.RequestedPrincipalContextLookup;
import se.litsec.shibboleth.idp.authn.service.AuthnContextService;

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

  /** Strategy used to locate the requested principal context. */
  @SuppressWarnings("rawtypes")
  protected static Function<ProfileRequestContext, RequestedPrincipalContext> requestedPrincipalLookupStrategy = Functions
    .compose(new RequestedPrincipalContextLookup(), authenticationContextLookupStrategy);

  /** Strategy used to locate the AuthnContextClassContext. */
  @SuppressWarnings("rawtypes")
  protected static Function<ProfileRequestContext, AuthnContextClassContext> authnContextClassLookupStrategy = Functions
    .compose(new AuthnContextClassContextLookup(), authenticationContextLookupStrategy);
  
  /** Sorter to be used for finding the most preferred URI according to the Shibboleth weigth map. */
  protected final Comparator<Principal> principalComparator = (p1, p2) -> {
    Integer w1 = this.authnContextweightMap.get(p1);
    Integer w2 = this.authnContextweightMap.get(p2);
    return Integer.compare(w1 != null ? w1 : 0, w2 != null ? w2 : 0);
  };

  /** {@inheritDoc} */
  @Override
  public void initializeContext(ProfileRequestContext<?, ?> context) throws ExternalAutenticationErrorCodeException {
    final String logId = this.getLogString(context);

    // Get the requested principals (from the AuthnRequest)
    //
    RequestedPrincipalContext requestedPrincipalContext = requestedPrincipalLookupStrategy.apply(context);
    List<String> requstedPrincipals;
    if (requestedPrincipalContext == null) {
      log.info("No RequestedPrincipalContext available - no AuthnContextClassRefs in AuthnRequest [{}]", logId);
      requstedPrincipals = Collections.emptyList();
    }
    else {
      // Sort the URI:s so the ones most prefered by the IdP ends up first in the list.
      //
      requstedPrincipals = requestedPrincipalContext.getRequestedPrincipals()
        .stream()
        .filter(AuthnContextClassRefPrincipal.class::isInstance)
        .sorted(principalComparator.reversed())
        .map(Principal::getName)
        .collect(Collectors.toList());
    }

    log.debug("Initializing RequestedAuthnContextClassContext with AuthnContextClassRef URI:s: {} [{}]", requestedPrincipalContext, logId);
    this.addAuthnContextClassContext(context, new AuthnContextClassContext(requstedPrincipals));
  }

  /** {@inheritDoc} */
  @Override
  public AuthnContextClassContext getAuthnContextClassContext(ProfileRequestContext<?, ?> context)
      throws ExternalAutenticationErrorCodeException {
    AuthnContextClassContext authnContextClassContext = authnContextClassLookupStrategy.apply(context);
    if (authnContextClassContext == null) {
      log.error("No AuthnContextClassContext available [{}]", this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.REQUEST_UNSUPPORTED, "Missing AuthnContextClassContext");
    }
    return authnContextClassContext;
  }

  /**
   * Adds the supplied {@code AuthnContextClassContext} to the request context
   * 
   * @param context
   *          the request context
   * @param authnContextClassContext
   *          the context to add
   * @throws ExternalAutenticationErrorCodeException
   *           if no context exists
   */
  protected void addAuthnContextClassContext(ProfileRequestContext<?, ?> context, AuthnContextClassContext authnContextClassContext)
      throws ExternalAutenticationErrorCodeException {
    AuthenticationContext authnContext = authenticationContextLookupStrategy.apply(context);
    if (authnContext == null) {
      log.error("No AuthenticationContext available [{}]", this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.REQUEST_UNSUPPORTED, "Missing AuthenticationContext");
    }
    authnContext.addSubcontext(authnContextClassContext, true);
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
      List<String> defaultUris = this.getSupportedAuthnContextClassRefs(context);
      log.info("No AuthnContext URI:s given in AuthnRequest - using IdP default(s): {} [{}]", defaultUris, logId);

      // Replace current context with new one.
      this.addAuthnContextClassContext(context, new AuthnContextClassContext(defaultUris));

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
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getSupportedAuthnContextClassRefs(ProfileRequestContext<?, ?> context) {
    AuthenticationContext authenticationContext = authenticationContextLookupStrategy.apply(context);
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
      .sorted(principalComparator.reversed())
      .map(Principal::getName)
      .collect(Collectors.toList());

    log.debug("Supported AuthnContextClassRef URI:s by flow '{}': {}", this.flowName, uris);
    return uris;    
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getPossibleAuthnContextClassRefs(ProfileRequestContext<?, ?> context)
      throws ExternalAutenticationErrorCodeException {

    AuthnContextClassContext authnContextContext = this.getAuthnContextClassContext(context);
    List<String> possibleUris = authnContextContext.getAuthnContextClassRefs();
    
    if (possibleUris.isEmpty()) {
      final String msg = "No AuthnContext URI:s can be used to authenticate user";
      log.info("{} - can not proceed [{}]", msg, this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.REQUEST_UNSUPPORTED, msg);
    }

    return possibleUris;
  }

  /** {@inheritDoc} */
  @Override
  public String getReturnAuthnContextClassRef(ProfileRequestContext<?, ?> context, String authnContextUri)
      throws ExternalAutenticationErrorCodeException {
    
    AuthnContextClassContext authnContextContext = this.getAuthnContextClassContext(context);
    
    String uri = null;
    
    if (authnContextUri == null) {
      uri = !authnContextContext.getAuthnContextClassRefs().isEmpty() 
          ? authnContextContext.getAuthnContextClassRefs().get(0) : null;  
    }
    else {
      uri = authnContextContext.getAuthnContextClassRefs().contains(authnContextUri) ? authnContextUri : null;
    }
    
    if (uri == null) {
      // This should never happen!
      final String msg = "No AuthnContext URI:s can be used to authenticate user";
      log.info("{} - can not proceed [{}]", msg, this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.REQUEST_UNSUPPORTED, msg); 
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
