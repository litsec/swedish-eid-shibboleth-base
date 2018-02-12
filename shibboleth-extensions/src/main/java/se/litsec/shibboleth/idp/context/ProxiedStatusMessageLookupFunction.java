/*
 * Copyright 2017-2018 Litsec AB
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
package se.litsec.shibboleth.idp.context;

import org.opensaml.profile.context.ProfileRequestContext;

/**
 * Lookup function used when building assigning the {@code StatusMessage} element of a {@code Status} element of a SAML2
 * {@code Response}. The function will check if the IdP is running in "proxy mode" and use the {@code StatusMessage}
 * from the stored {@link ProxiedStatusContext} if available. Otherwise it will revert to the
 * {@link ExtendedSpringStatusMessageLookupFunction} function.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class ProxiedStatusMessageLookupFunction extends ExtendedSpringStatusMessageLookupFunction {

  /** {@inheritDoc} */
  @Override
  public String apply(@SuppressWarnings("rawtypes") final ProfileRequestContext input) {
    String msg = null;
    if (input != null) {
      ProxiedStatusContext context = input.getSubcontext(ProxiedStatusContext.class, false);
      if (context != null && context.getStatus() != null && context.getStatus().getStatusMessage() != null) {
        msg = context.getStatus().getStatusMessage().getMessage();
      }
    }
    return msg != null ? msg : super.apply(input);
  }

}
