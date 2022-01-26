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

import javax.annotation.Nullable;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;

import net.shibboleth.idp.profile.context.ProfileInterceptorContext;
import se.litsec.shibboleth.idp.authn.context.ClientTlsCertificateContext;
import se.litsec.shibboleth.idp.authn.context.strategy.ClientTlsCertificateContextLookup;

/**
 * An action that modifies the SubjectConfirmation for Holder-of-key.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@SuppressWarnings("rawtypes")
public class UpdateHokSubjectConfirmationAction extends AbstractHolderOfKeyAction {
  
  /** Class logger. */
  private final Logger log = LoggerFactory.getLogger(UpdateHokSubjectConfirmationAction.class);

  /** Strategy used to locate the {@link Assertion} to operate on. */
  private static Function<ProfileRequestContext, Assertion> assertionLookupStrategy = new AssertionStrategy();
  
  /** Strategy to find ClientTlsCertificateContext. */
  private static ClientTlsCertificateContextLookup clientCertLookupStrategy = new ClientTlsCertificateContextLookup();
  
  /** {@inheritDoc} */
  @Override
  protected void doExecute(final ProfileRequestContext profileRequestContext, final ProfileInterceptorContext interceptorContext) {

    if (!this.isHokActive()) {
      return;
    }
    
    final Assertion assertion = assertionLookupStrategy.apply(profileRequestContext);
    if (assertion == null) {
      // No Assertion present if there is an error response ...
      return;
    }
    
    final ClientTlsCertificateContext clientTlsCertContext = clientCertLookupStrategy.apply(profileRequestContext);
    if (clientTlsCertContext == null) {
      log.error("Missing ClientTlsCertificateContext - client certificate can not be found");
      ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
      return;
    }
    
    if (assertion.getSubject() == null) {
      // This is really wrong ...
      return;
    }
    for (final SubjectConfirmation sc : assertion.getSubject().getSubjectConfirmations()) {
      if (sc.getSubjectConfirmationData() == null) {
        continue;
      }
      if (SubjectConfirmation.METHOD_BEARER.equals(sc.getMethod())) {
        sc.setMethod(SubjectConfirmation.METHOD_HOLDER_OF_KEY);
        sc.getSubjectConfirmationData().getUnknownXMLObjects().add(clientTlsCertContext.getObjectForSubjectConfirmation());
        log.debug("SubjectConfirmation updated to {}", SubjectConfirmation.METHOD_HOLDER_OF_KEY);
      }
    }
    
  }
  
  /**
   * For finding the Assertion.
   */
  private static class AssertionStrategy implements Function<ProfileRequestContext, Assertion> {

    /** {@inheritDoc} */
    @Override
    public Assertion apply(@Nullable final ProfileRequestContext input) {
      if (input != null && input.getOutboundMessageContext() != null) {
        final Object outboundMessage = input.getOutboundMessageContext().getMessage();

        if (outboundMessage != null) {
          if (outboundMessage instanceof Assertion) {
            return (Assertion) outboundMessage;
          }
          else if (outboundMessage instanceof Response) {
            Response r = (Response) outboundMessage;
            if (!r.getAssertions().isEmpty()) {
              return r.getAssertions().get(0);
            }
          }
        }
      }
      return null;
    }
  }

}
