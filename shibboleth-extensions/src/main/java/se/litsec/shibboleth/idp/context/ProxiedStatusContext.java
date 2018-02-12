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

import org.opensaml.messaging.context.BaseContext;
import org.opensaml.saml.saml2.core.Status;

/**
 * When Shibboleth is running as a Proxy IdP the authentication process (i.e., the SP) may save the {@code Status}
 * received from the authenticating party in a context. This may later be used when compiling the {@code Response}
 * message.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class ProxiedStatusContext extends BaseContext {

  /** The Status object. */
  private Status status;

  /**
   * Constructor assigning the status.
   * 
   * @param status
   *          the status element
   */
  public ProxiedStatusContext(Status status) {
    if (status == null) {
      throw new IllegalArgumentException("status must not be null");
    }
    this.status = status;
  }

  /**
   * Returns the contained {@code Status} element.
   * 
   * @return the {@code Status} element
   */
  public Status getStatus() {
    return this.status;
  }

}
