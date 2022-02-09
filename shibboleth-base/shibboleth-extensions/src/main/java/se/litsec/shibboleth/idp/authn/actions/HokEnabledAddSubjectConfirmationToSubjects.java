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
package se.litsec.shibboleth.idp.authn.actions;

import javax.annotation.Nonnull;

import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.OutboundMessageContextLookup;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.profile.impl.AddSubjectConfirmationToSubjects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import se.litsec.shibboleth.idp.authn.context.HolderOfKeyContext;
import se.litsec.shibboleth.idp.authn.context.strategy.HolderOfKeyContextLookup;

@SuppressWarnings("rawtypes")
public class HokEnabledAddSubjectConfirmationToSubjects extends AddSubjectConfirmationToSubjects {
  
  private final Logger log = LoggerFactory.getLogger(HokEnabledAddSubjectConfirmationToSubjects.class);
  
  private static HolderOfKeyContextLookup hokLookup = new HolderOfKeyContextLookup();
  
  private static Function<ProfileRequestContext, Response> responseLookup =
      Functions.compose(new MessageLookup<>(Response.class), new OutboundMessageContextLookup());
  
  private boolean hokActive = false;

  public HokEnabledAddSubjectConfirmationToSubjects() {
    super();
  }
  
  @Override
  protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
    super.doExecute(profileRequestContext);
    if (this.hokActive) {
      final HolderOfKeyContext hokContext = hokLookup.apply(profileRequestContext);
      if (hokContext == null || !hokContext.isIssueHokAssertion()) {
        return;
      }      
      
      final Response response = responseLookup.apply(profileRequestContext);
      if (response == null) {
        return;  // Should never happen - checked by super class
      }
      else if (response.getAssertions().isEmpty()) {
        return;
      }
      
      final Assertion assertion = response.getAssertions().get(0);

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
          sc.getSubjectConfirmationData().getUnknownXMLObjects().add(hokContext.getObjectForSubjectConfirmation());
          log.debug("SubjectConfirmation method updated to {}", SubjectConfirmation.METHOD_HOLDER_OF_KEY);
        }
      }
      
    }
  }
  
  public void setHokActive(final boolean hokActive) {
    this.hokActive = hokActive;
  }

}
