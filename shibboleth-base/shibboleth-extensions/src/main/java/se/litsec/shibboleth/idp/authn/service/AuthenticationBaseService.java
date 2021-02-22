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

import org.opensaml.profile.context.ProfileRequestContext;

import se.litsec.shibboleth.idp.authn.ExternalAutenticationErrorCodeException;

/**
 * Base interface for authentication services.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public interface AuthenticationBaseService {

  /**
   * Initializes the supplied context with the service's particular context (if any).
   * 
   * @param context
   *          the request context to update
   * @throws ExternalAutenticationErrorCodeException
   *           if the context cannot be initialized
   */
  void initializeContext(final ProfileRequestContext context) throws ExternalAutenticationErrorCodeException;

  /**
   * Performs processing of the recived request.
   * 
   * @param context
   *          the context to validate and update
   * @throws ExternalAutenticationErrorCodeException
   *           if the requested AuthnContextClass URI:s are invalid in the context they are applied
   */
  void processRequest(final ProfileRequestContext context) throws ExternalAutenticationErrorCodeException;
}
