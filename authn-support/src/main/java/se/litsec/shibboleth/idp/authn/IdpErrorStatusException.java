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
package se.litsec.shibboleth.idp.authn;

import org.opensaml.saml.saml2.core.Status;

/**
 * Exception that Proxy IdP:s may use to signal errors received from the SP-part, or by "ordinary" IdP:s to signal a
 * detailed error.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class IdpErrorStatusException extends Exception {

  /** For serializing. */
  private static final long serialVersionUID = -8301077213844939978L;

  /** The error status. */
  private Status status;

  /**
   * Constructor accepting the status object.
   * 
   * @param status
   *          the error status
   */
  public IdpErrorStatusException(Status status) {
    this.status = status;
  }

  /**
   * Constructor accepting a status object and an error message.
   * 
   * @param status
   *          the error status
   * @param msg
   *          the error message
   */
  public IdpErrorStatusException(Status status, String msg) {
    super(msg);
    this.status = status;
  }

  /**
   * Returns the error status object
   * 
   * @return the status object
   */
  public Status getStatus() {
    return this.status;
  }

}