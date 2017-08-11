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
