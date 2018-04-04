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
package se.litsec.shibboleth.idp.authn.service;

import java.util.List;

import org.opensaml.profile.context.ProfileRequestContext;

import se.litsec.shibboleth.idp.authn.ExternalAutenticationErrorCodeException;
import se.litsec.shibboleth.idp.authn.context.AuthnContextClassContext;

/**
 * Provides IdP services for handling Authentication Contexts (level of assurance).
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public interface AuthnContextService extends AuthenticationBaseService {

  /**
   * Returns the current {@link AuthnContextClassContext}.
   * 
   * @param context
   *          the request context
   * @return the current {@link AuthnContextClassContext}, or {@code null} if none is available
   * @throws ExternalAutenticationErrorCodeException
   *           if no context exists
   */
  AuthnContextClassContext getAuthnContextClassContext(ProfileRequestContext<?, ?> context) throws ExternalAutenticationErrorCodeException;

  /**
   * If a relying party does not specify an AuthnContext URI in the AuthnContext the IdP chooses a default one to use.
   * The default implementation returns only one URI, but other implementations may return several (for example if the
   * IdP is a ProxyIdP).
   * 
   * @param context
   *          the request context
   * @return a list of default AuthnContext URI(s)
   */
  List<String> getDefaultAuthnContextClassRefs(ProfileRequestContext<?, ?> context);

  /**
   * Returns a list of AuthnContextClassRef URI:s (level of assurance URI:s) that is supported by the current
   * authentication method.
   * 
   * @param context
   *          the profile context
   * @return a list of supported AuthnContextClassRef URI:s
   */
  List<String> getSupportedAuthnContextClassRefs(ProfileRequestContext<?, ?> context);

  /**
   * An IdP may support several authentication context URI:s within the same authenticator (authentication method), and
   * a SP may request any number of {@code AuthnContextClassRef} URI:s in the authentication request. The
   * {@link #processRequest(ProfileRequestContext)} method will process the list of requested URI:s based on what the
   * IdP supports and remove those not relevant. When it is time to authenticate the user the IdP will need to know
   * under which authentication context the authentication should be performed. This method will return a list of
   * possible authentication context URI:s to use where the most preferred IdP choice is placed first in the list.
   * <p>
   * Note that the method will only return actual authentication context URI:s describing an authentication type, and
   * not their corresponding sig-message versions.
   * </p>
   * 
   * @param context
   *          the profile context
   * @param signMessage
   *          an indication whether this is a "authentication for signature" flow and the IdP will display a sign
   *          message
   * @return a list of possible URI:s
   * @throws ExternalAutenticationErrorCodeException
   *           for processing errors
   */
  List<String> getPossibleAuthnContextClassRefs(ProfileRequestContext<?, ?> context, boolean signMessage)
      throws ExternalAutenticationErrorCodeException;

  /**
   * When the IdP is about to issue an assertion it includes the {@code AuthnContextClassRef} element holding the URI
   * describing how the user was authenticated. This method will return this specific URI.
   * 
   * @param context
   *          the profile context
   * @param authnContextUri
   *          the URI under which the IdP authenticated the user (may be {@code null})
   * @param displayedSignMessage
   *          flag telling if the IdP displayed a sign message
   * @return the LoA URI to include in the assertion back to the SP
   * @throws ExternalAutenticationErrorCodeException
   *           for errors in processing
   */
  String getReturnAuthnContextClassRef(ProfileRequestContext<?, ?> context, String authnContextUri, boolean displayedSignMessage)
      throws ExternalAutenticationErrorCodeException;

}
