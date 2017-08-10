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
