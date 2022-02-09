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
package se.litsec.shibboleth.idp.profile.interceptor;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.checkerframework.checker.nullness.qual.Nullable;
import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.google.common.base.Predicate;

import net.shibboleth.utilities.java.support.net.BasicURLComparator;
import net.shibboleth.utilities.java.support.net.URIComparator;
import net.shibboleth.utilities.java.support.net.URIException;
import se.litsec.shibboleth.idp.authn.context.HolderOfKeyContext;

/**
 * Condition that tells if the Holder-of-key profile is active.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class IsHokActiveCondition implements Predicate<ProfileRequestContext<?, ?>>, InitializingBean {

  /** Class logger. */
  private final Logger log = LoggerFactory.getLogger(IsHokActiveCondition.class);

  /** Is the Holder-of-key profile active? */
  private boolean hokActive = false;

  /** The IdP metadata. */
  private EntityDescriptor idpMetadata;

  /** The current HTTP servlet request. */
  private HttpServletRequest httpServletRequest;

  /** Strategy used to locate the {@link AuthnRequest} to operate on. */
  @SuppressWarnings("rawtypes")
  private static Function<ProfileRequestContext, AuthnRequest> requestLookupStrategy = Functions.compose(
    new MessageLookup<>(AuthnRequest.class), new InboundMessageContextLookup());

  /** For comparing URL:s. */
  private static URIComparator urlComparator = new BasicURLComparator();

  static {
    ((BasicURLComparator) urlComparator).setCaseInsensitive(true);
  }

  /**
   * Constructor.
   */
  public IsHokActiveCondition() {
  }

  /** {@inheritDoc} */
  @Override
  public boolean apply(@Nullable final ProfileRequestContext<?, ?> input) {
    if (!this.hokActive) {
      return false;
    }

    // Get the "received on" URL.
    //
    final AuthnRequest authnRequest = requestLookupStrategy.apply(input);
    if (authnRequest == null) {
      log.warn("No AuthnRequest available in context");
      return false;
    }
    final String receivedOn = authnRequest.getDestination();
    if (!StringUtils.hasText(receivedOn)) {
      log.info("Invalid AuthnRequest - Missing Destination attribute");
      return false;
    }
    final String method = httpServletRequest.getMethod();

    final List<SingleSignOnService> ssoServices =
        Optional.ofNullable(idpMetadata.getIDPSSODescriptor(SAMLConstants.SAML20P_NS))
          .map(IDPSSODescriptor::getSingleSignOnServices)
          .orElse(Collections.emptyList());

    for (final SingleSignOnService sso : ssoServices) {
      if ("GET".equalsIgnoreCase(method)) {
        if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(sso.getBinding())
            && compareUrls(receivedOn, sso.getLocation())) {
          log.debug("Request received on {} - Not a Holder-of-key endpoint", receivedOn);
          return false;
        }
        else if (HolderOfKeyContext.HOK_WEBSSO_PROFILE_URI.equals(sso.getBinding())
            && SAMLConstants.SAML2_REDIRECT_BINDING_URI
              .equals(sso.getUnknownAttributes().get(HolderOfKeyContext.HOK_PROTOCOL_BINDING_ATTRIBUTE))
            && compareUrls(receivedOn, sso.getLocation())) {
          log.debug("Request received on {} - This is a Holder-of-key endpoint", receivedOn);
          return true;
        }
      }
      else if ("POST".equalsIgnoreCase(method)) {
        if (SAMLConstants.SAML2_POST_BINDING_URI.equals(sso.getBinding())
            && compareUrls(receivedOn, sso.getLocation())) {
          log.debug("Request received on {} - Not a Holder-of-key endpoint", receivedOn);
          return false;
        }
        else if (HolderOfKeyContext.HOK_WEBSSO_PROFILE_URI.equals(sso.getBinding())
            && SAMLConstants.SAML2_POST_BINDING_URI
              .equals(sso.getUnknownAttributes().get(HolderOfKeyContext.HOK_PROTOCOL_BINDING_ATTRIBUTE))
            && compareUrls(receivedOn, sso.getLocation())) {
          log.debug("Request received on {} - This is a Holder-of-key endpoint", receivedOn);
          return true;
        }
      }
    }
    log.info("AuthnRequest/Destination ({}) did not match any Location in SingleSignOnService", receivedOn);

    return false;
  }

  private static boolean compareUrls(final String u1, final String u2) {
    try {
      return urlComparator.compare(u1, u2);
    }
    catch (URIException e) {
      return false;
    }
  }

  /**
   * Assigns whether the Holder-of-key profile is active.
   * 
   * @param hokActive
   *          whether HoK is active
   */
  public void setHokActive(final boolean hokActive) {
    this.hokActive = hokActive;
  }

  /**
   * Assigns the IdP metadata.
   * 
   * @param idpMetadata
   *          the IdP metadata
   */
  public void setIdpMetadata(final EntityDescriptor idpMetadata) {
    this.idpMetadata = idpMetadata;
  }

  /**
   * Assigns the current HTTP servlet request.
   * 
   * @param httpServletRequest
   *          the request
   */
  public void setHttpServletRequest(final HttpServletRequest httpServletRequest) {
    this.httpServletRequest = httpServletRequest;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.idpMetadata, "idpMetadata must be assigned");
    Assert.notNull(this.httpServletRequest, "httpServletRequest must be assigned");
  }

}
