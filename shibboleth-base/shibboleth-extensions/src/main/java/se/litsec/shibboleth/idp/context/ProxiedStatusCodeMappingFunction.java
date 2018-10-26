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
