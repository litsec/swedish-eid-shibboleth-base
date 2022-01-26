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

import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import net.shibboleth.idp.profile.context.ProfileInterceptorContext;
import net.shibboleth.utilities.java.support.net.BasicURLComparator;
import net.shibboleth.utilities.java.support.net.URIComparator;
import net.shibboleth.utilities.java.support.net.URIException;
import se.litsec.shibboleth.idp.authn.context.strategy.SAMLPeerEntityContextLookup;
import se.litsec.shibboleth.idp.authn.controller.AbstractExternalAuthenticationController.PeerMetadataContextLookup;

/**
 * Checks the the requesting SP has indicated that it want the response sent back on an AssertionConsumerService
 * dedicated for Holder-of-key.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@SuppressWarnings("rawtypes")
public class CheckHokAssertionConsumerServiceAction extends AbstractHolderOfKeyAction {

  /** Class logger. */
  private final Logger log = LoggerFactory.getLogger(CheckHokAssertionConsumerServiceAction.class);

  /** Strategy used to locate the {@link AuthnRequest} to operate on. */
  private static Function<ProfileRequestContext, AuthnRequest> requestLookupStrategy = Functions.compose(
    new MessageLookup<>(AuthnRequest.class), new InboundMessageContextLookup());

  /** Strategy used to locate the SP {@link EntityDescriptor} (metadata). */
  private static Function<ProfileRequestContext, EntityDescriptor> peerMetadataLookupStrategy = Functions.compose(
    new PeerMetadataContextLookup(), Functions.compose(new SAMLPeerEntityContextLookup(), new InboundMessageContextLookup()));
  
  /** For comparing URL:s. */
  private static URIComparator urlComparator = new BasicURLComparator();
  
  static {
    ((BasicURLComparator) urlComparator).setCaseInsensitive(true);
  }

  /** {@inheritDoc} */
  @Override
  protected void doExecute(final ProfileRequestContext profileRequestContext, final ProfileInterceptorContext interceptorContext) {

    if (!this.isHokActive()) {
      return;
    }

    final AuthnRequest authnRequest = requestLookupStrategy.apply(profileRequestContext);
    if (authnRequest == null) {
      return; // ?
    }

    if (authnRequest.getAssertionConsumerServiceURL() != null) {
      if (this.isHokAssertionConsumerService(authnRequest.getAssertionConsumerServiceURL(), profileRequestContext)) {
        log.info("{} Bad AuthnRequest - AssertionConsumerServiceURL {} is not for Holder-of-key", 
          this.getLogPrefix(), authnRequest.getAssertionConsumerServiceURL());
        ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
      }
    }
    else if (authnRequest.getAssertionConsumerServiceIndex() != null) {
      if (this.isHokAssertionConsumerService(authnRequest.getAssertionConsumerServiceIndex(), profileRequestContext)) {
        log.info("{} Bad AuthnRequest - AssertionConsumerServiceIndex {} is not for Holder-of-key", 
          this.getLogPrefix(), authnRequest.getAssertionConsumerServiceIndex());
        ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
      }
    }
    else {
      // Not a valid request.
      log.info("{} Invalid AuthnRequest - Neither AssertionConsumerServiceURL nor AssertionConsumerServiceIndex is present",
        this.getLogPrefix());
      ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
    }
  }

  private boolean isHokAssertionConsumerService(final String url, final ProfileRequestContext profileRequestContext) {
    final AssertionConsumerService acs = this.getAssertionConsumerServices(profileRequestContext).stream()
        .filter(a -> {
          try {
            return urlComparator.compare(url, a.getLocation());
          }
          catch (final URIException e) {
            return false;
          }          
        })
        .findFirst()
        .orElse(null);
    if (acs == null) {
      log.info("{} Bad AuthnRequest - AssertionConsumerServiceURL {} is not present in SP metadata", this.getLogPrefix(), url);
      return false;
    }
    return isHoKAssertionConsumerService(acs);
  }

  private boolean isHokAssertionConsumerService(final Integer index, final ProfileRequestContext profileRequestContext) {
    final AssertionConsumerService acs = this.getAssertionConsumerServices(profileRequestContext).stream()
        .filter(a -> index.equals(a.getIndex()))
        .findFirst()
        .orElse(null);
    if (acs == null) {
      log.info("{} Bad AuthnRequest - AssertionConsumerServiceIndex {} is not present in SP metadata", this.getLogPrefix(), index);
      return false;
    }
    return isHoKAssertionConsumerService(acs);
  }
  
  /**
   * Predicate that tells if the supplied {@code AssertionConsumerService} is a HoK endpoint.
   * 
   * @param acs
   *          the AssertionConsumerService to test
   * @return true if the supplied object is a HoK endpoint and false otherwise
   */
  private static boolean isHoKAssertionConsumerService(final AssertionConsumerService acs) {
    return HOK_WEBSSO_PROFILE_URI.equals(acs.getBinding());
  }

  /**
   * Gets hold of all AssertionConsumerService from the SP metadata.
   * 
   * @param profileRequestContext
   *          the context
   * @return a list of all declared AssertionConsumerService elements
   */
  private List<AssertionConsumerService> getAssertionConsumerServices(final ProfileRequestContext profileRequestContext) {
    final EntityDescriptor spMetadata = peerMetadataLookupStrategy.apply(profileRequestContext);
    if (spMetadata == null) {
      return Collections.emptyList();
    }
    return Optional.ofNullable(spMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS))
      .map(SPSSODescriptor::getAssertionConsumerServices)
      .orElse(Collections.emptyList());
  }

}
