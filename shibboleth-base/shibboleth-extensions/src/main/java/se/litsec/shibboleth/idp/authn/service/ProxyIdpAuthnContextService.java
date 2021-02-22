/*
 * Copyright 2017-2021 Litsec AB
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
package se.litsec.shibboleth.idp.authn.service;

import java.util.List;

import org.opensaml.profile.context.ProfileRequestContext;

import se.litsec.shibboleth.idp.authn.ExternalAutenticationErrorCodeException;
import se.litsec.shibboleth.idp.authn.context.AuthnContextClassContext;

/**
 * Extends the {@link AuthnContextService} interface with methods useful for a Proxy IdP.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public interface ProxyIdpAuthnContextService extends AuthnContextService {

  /**
   * The method matches the supplied URI:s from the IdP:s assurance certification against the
   * {@link AuthnContextClassContext} for the current request, and updates this context, i.e., removes those not
   * supported by the IdP.
   * <p>
   * If no AuthnContext URI:s remains in the {@link AuthnContextClassContext} after matching, an error is thrown since
   * this means that the SP request and what the IdP supports does not match.
   * </p>
   * <p>
   * If the supplied IdP assurance certification list is empty, no matching is performed.
   * </p>
   * <p>
   * Finally, a list of URI:s to include in the AuthnRequest to be sent to the IdP is returned. These are also saved in
   * the current {@link AuthnContextClassContext}.
   * </p>
   * 
   * @param context
   *          the request context
   * @param assuranceURIs
   *          IdP assurance certification URI:s
   * @return a list of URI:s to include in the AuthnRequest to be sent to the IdP
   * @throws ExternalAutenticationErrorCodeException
   *           if no AuthnContext URI:s matches
   */
  List<String> getSendAuthnContextClassRefs(final ProfileRequestContext context, final List<String> assuranceURIs) 
      throws ExternalAutenticationErrorCodeException;

  /**
   * When the Proxy-IdP receives an assertion it contains an {@code AuthnContextClassRef} holding the URI describing how
   * the IdP authenticated the user. This method verifies that this URI matches any of the URI:s the IdP-Proxy SP
   * included in the AuthnRequest, and throws an exception otherwise.
   * 
   * @param context
   *          the profile context
   * @param authnContextUri
   *          the URI from the AuthnContextClassRef element of the assertion
   * @return the LoA URI to include in the assertion back to the SP
   * @throws ExternalAutenticationErrorCodeException
   *           if the issued URI can not be used in the Proxy-IdP assertion
   */
  @Override
  String getReturnAuthnContextClassRef(final ProfileRequestContext context, final String authnContextUri)
      throws ExternalAutenticationErrorCodeException;

  /**
   * A Proxy-IdP does not perform the authentication itself. Instead the
   * {@link #getSendAuthnContextClassRefs(ProfileRequestContext, List)} should be used.
   */
  @Override
  default List<String> getPossibleAuthnContextClassRefs(final ProfileRequestContext context)
      throws ExternalAutenticationErrorCodeException {
    throw new RuntimeException("Call to getPossibleAuthnContextClassRefs is not allowed for a Proxy-IdP");
  }

}
