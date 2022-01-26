/*
 * Copyright 2016-2022 Litsec AB
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

import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import net.shibboleth.idp.profile.context.ProfileInterceptorContext;
import net.shibboleth.idp.profile.interceptor.AbstractProfileInterceptorAction;

/**
 * Interceptor action that prevents SSO from happening. This should be used for signature services. 
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@SuppressWarnings("rawtypes")
public class SsoPreventionInterceptorAction extends AbstractProfileInterceptorAction {

  /** Class logger. */
  private final Logger log = LoggerFactory.getLogger(SsoPreventionInterceptorAction.class);
  
  /** Strategy used to locate the {@link AuthnRequest} to operate on. */
  protected static Function<ProfileRequestContext, AuthnRequest> requestLookupStrategy = Functions.compose(
    new MessageLookup<>(AuthnRequest.class), new InboundMessageContextLookup());

  /** {@inheritDoc} */
  @Override
  protected void doExecute(final ProfileRequestContext profileRequestContext, final ProfileInterceptorContext interceptorContext) {
    
    AuthnRequest authnRequest = requestLookupStrategy.apply(profileRequestContext);
    if (authnRequest != null) {
      if (authnRequest.isForceAuthn() == null || authnRequest.isForceAuthn() == Boolean.FALSE) {
        log.info("{} AuthnRequest '{}' from '{}' has does not require forced authentication - enforcing it", 
          this.getLogPrefix(), authnRequest.getID(), authnRequest.getIssuer() != null ? authnRequest.getIssuer().getValue() : "-");
        authnRequest.setForceAuthn(true);
      }
    }
  }

}
