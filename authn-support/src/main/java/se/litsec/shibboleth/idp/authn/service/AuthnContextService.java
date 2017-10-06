/*
 * The swedish-eid-shibboleth-base is an open-source package that provides
 * an easy-to-use re-packaging of the Shibboleth Identity Provider for use
 * with the Swedish eID Framework. 
 *
 * More details on <https://github.com/litsec/swedish-eid-shibboleth-base> 
 * Copyright (C) 2017 Litsec AB
 * 
 * This program is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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
   * @throws if
   *           no context exists
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

}
