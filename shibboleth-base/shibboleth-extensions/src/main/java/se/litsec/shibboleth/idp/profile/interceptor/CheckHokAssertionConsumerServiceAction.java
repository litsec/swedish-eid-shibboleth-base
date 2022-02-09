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

import java.util.List;
import java.util.Optional;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import net.shibboleth.idp.profile.context.ProfileInterceptorContext;
import net.shibboleth.utilities.java.support.net.BasicURLComparator;
import net.shibboleth.utilities.java.support.net.URIComparator;
import net.shibboleth.utilities.java.support.net.URIException;
import se.litsec.shibboleth.idp.authn.context.HolderOfKeyContext;
import se.litsec.shibboleth.idp.authn.context.strategy.HolderOfKeyContextLookup;
import se.litsec.shibboleth.idp.authn.context.strategy.SAMLPeerEntityContextLookup;

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

  /** Strategy to find a HolderOfKeyContext. */
  private static HolderOfKeyContextLookup hokLookupStrategy = new HolderOfKeyContextLookup();

  /** Strategy used to locate the {@link AuthnRequest} to operate on. */
  private static Function<ProfileRequestContext, AuthnRequest> requestLookupStrategy = Functions.compose(
    new MessageLookup<>(AuthnRequest.class), new InboundMessageContextLookup());

  /** Strategy for finding the SAMLPeerEntityContext. */
  private static Function<ProfileRequestContext, SAMLPeerEntityContext> peerEntityContextLookupStrategy =
      Functions.compose(new SAMLPeerEntityContextLookup(), new InboundMessageContextLookup());

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

    HolderOfKeyContext holderOfKeyContext = hokLookupStrategy.apply(profileRequestContext);
    if (holderOfKeyContext == null) {
      holderOfKeyContext = new HolderOfKeyContext();
      profileRequestContext.addSubcontext(holderOfKeyContext);
    }    

    final AuthnRequest authnRequest = requestLookupStrategy.apply(profileRequestContext);
    if (authnRequest == null) {
      return; // ?
    }
    final SAMLMetadataContext samlMetadataContext =
        Optional.ofNullable(peerEntityContextLookupStrategy.apply(profileRequestContext))
          .map(p -> p.getSubcontext(SAMLMetadataContext.class, false))
          .orElse(null);
    if (samlMetadataContext == null) {
      log.warn("{} Missing SAML metadata context", this.getLogPrefix());
      ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
      return;
    }
    // Unsure if everything is set ...
    if (samlMetadataContext.getRoleDescriptor() == null && samlMetadataContext.getEntityDescriptor() != null) {
      samlMetadataContext.setRoleDescriptor(
        samlMetadataContext.getEntityDescriptor().getSPSSODescriptor(SAMLConstants.SAML20P_NS));
    }
    if (samlMetadataContext.getRoleDescriptor() == null || !(samlMetadataContext.getRoleDescriptor() instanceof SPSSODescriptor)) {
      log.warn("{} Unknown RoleDescriptor ...", this.getLogPrefix());
      return;
    }
    final SPSSODescriptor ssoDescriptor = SPSSODescriptor.class.cast(samlMetadataContext.getRoleDescriptor());
    final List<AssertionConsumerService> acsList = ssoDescriptor.getAssertionConsumerServices();

    AssertionConsumerService acs = null;
    boolean hokEndpoint = false;
    boolean notSure = false;

    if (authnRequest.getAssertionConsumerServiceURL() != null) {
      final String url = authnRequest.getAssertionConsumerServiceURL();
      for (final AssertionConsumerService a : acsList) {
        if (compareUrls(url, a.getLocation())) {
          if (HolderOfKeyContext.HOK_WEBSSO_PROFILE_URI.equals(a.getBinding())) {
            // TODO: Should check that it is POST ...
            acs = a;
            hokEndpoint = true;
          }
          else if (SAMLConstants.SAML2_POST_BINDING_URI.equals(a.getBinding())) {
            if (acs == null) {
              acs = a;
              hokEndpoint = false;
            }
            else {
              notSure = true;
            }
          }
        }
      }
    }
    else if (authnRequest.getAssertionConsumerServiceIndex() != null) {
      acs = acsList.stream()
        .filter(a -> authnRequest.getAssertionConsumerServiceIndex().equals(a.getIndex()))
        .findFirst()
        .orElse(null);
      if (acs != null) {
        hokEndpoint = HolderOfKeyContext.HOK_WEBSSO_PROFILE_URI.equals(acs.getBinding());
      }
    }
    else {
      // Find default ACS.
      int index = Integer.MAX_VALUE;
      for (final AssertionConsumerService a : acsList) {
        if (a.isDefault()) {
          acs = a;
          break;
        }
        else if (a.getIndex() != null && a.getIndex() < index) {
          acs = a;
          index = a.getIndex();
        }
      }
      if (acs != null) {
        hokEndpoint = HolderOfKeyContext.HOK_WEBSSO_PROFILE_URI.equals(acs.getBinding());
      }
    }

    if (acs == null) {
      // Not a valid request.
      log.info("{} Invalid AuthnRequest - Could not determine which AssertionConsumerService location to use",
        this.getLogPrefix());
      ActionSupport.buildEvent(profileRequestContext, "MessageAuthenticationError");
      return;
    }

    holderOfKeyContext.setAssertionConsumerService(acs);
    holderOfKeyContext.setAcsDefinite(!notSure);

    // Since Shibboleth does not have support for HoK we need to cheat a bit now.
    // Let's patch the metadata entry stored in the request so that it appears to be
    // an ordinary ACS.
    //
    if (hokEndpoint) {
      try {
        final SPSSODescriptor clone = XMLObjectSupport.cloneXMLObject(ssoDescriptor);
        clone.setParent(samlMetadataContext.getEntityDescriptor());
        for (final AssertionConsumerService a : clone.getAssertionConsumerServices()) {
          if (HolderOfKeyContext.HOK_WEBSSO_PROFILE_URI.equals(a.getBinding())) {
            a.setBinding(acs.getUnknownAttributes().getOrDefault(
              HolderOfKeyContext.HOK_PROTOCOL_BINDING_ATTRIBUTE, SAMLConstants.SAML2_POST_BINDING_URI));
            a.getUnknownAttributes().remove(HolderOfKeyContext.HOK_PROTOCOL_BINDING_ATTRIBUTE);
          }
        }
        samlMetadataContext.setRoleDescriptor(clone);
      }
      catch (final MarshallingException | UnmarshallingException e) {
        log.error("{} Failed to clone SPSSODescriptor ...", this.getLogPrefix(), e);
      }
    }

  }

  private static boolean compareUrls(final String u1, final String u2) {
    try {
      return urlComparator.compare(u1, u2);
    }
    catch (URIException e) {
      return false;
    }
  }

}
