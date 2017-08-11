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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.profile.impl.AddStatusToResponse;

/**
 * A function that is used to obtain the SAML2 Status codes to add to the resulting {@code Status} element. The function
 * first checks if the IdP is running in proxy mode, and if so, copies the status codes from the
 * {@link ProxiedStatusContext}. If this context is not available, the function reverts to
 * {@link AddStatusToResponse.StatusCodeMappingFunction}.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class ProxiedStatusCodeMappingFunction extends AddStatusToResponse.StatusCodeMappingFunction {

  public ProxiedStatusCodeMappingFunction(Map<String, List<String>> mappings) {
    super(mappings);
  }

  /** {@inheritDoc} */
  @Override
  public List<String> apply(@SuppressWarnings("rawtypes") final ProfileRequestContext input) {
    List<String> codes = null;
    if (input != null) {
      ProxiedStatusContext context = input.getSubcontext(ProxiedStatusContext.class, false);
      if (context != null && context.getStatus() != null) {
        codes = new ArrayList<>();
        StatusCode statusCode = context.getStatus().getStatusCode();
        while (statusCode != null) {
          codes.add(statusCode.getValue());
          statusCode = statusCode.getStatusCode();
        }
      }
    }
    return codes != null ? codes : super.apply(input);
  }

}
