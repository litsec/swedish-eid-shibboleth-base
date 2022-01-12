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
package se.litsec.shibboleth.idp.authn.context;

import org.opensaml.messaging.context.BaseContext;

import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SADRequest;

/**
 * Handles {@code SADRequest} elements received in authentication requests from signature services.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class SignatureActivationDataContext extends BaseContext {

  /** The {@code SADRequest} extension. */
  private SADRequest sadRequest;

  /**
   * Constructor assigning the SAD request.
   * 
   * @param sadRequest
   *          the SAD request
   */
  public SignatureActivationDataContext(SADRequest sadRequest) {
    this.sadRequest = sadRequest;
  }

  /**
   * Returns the SAD request.
   * 
   * @return the SAD request
   */
  public SADRequest getSadRequest() {
    return this.sadRequest;
  }

}
