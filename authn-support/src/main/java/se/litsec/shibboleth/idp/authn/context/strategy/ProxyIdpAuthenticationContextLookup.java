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
package se.litsec.shibboleth.idp.authn.context.strategy;

import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import se.litsec.shibboleth.idp.authn.context.ProxyIdpAuthenticationContext;

/**
 * Lookup function for finding a {@link ProxyIdpAuthenticationContext}.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class ProxyIdpAuthenticationContextLookup implements ContextDataLookupFunction<AuthenticationContext, ProxyIdpAuthenticationContext> {

  /** {@inheritDoc} */
  @Override
  public ProxyIdpAuthenticationContext apply(AuthenticationContext input) {
    return input != null ? input.getSubcontext(ProxyIdpAuthenticationContext.class, false) : null;
  }

}
