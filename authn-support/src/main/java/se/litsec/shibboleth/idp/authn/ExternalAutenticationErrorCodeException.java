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

/**
 * If the service implementing an external authentication process needs to signal an error, it can either assign an
 * error code to the request as:
 * 
 * <pre>
 * {@code 
 * httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, authnEventId);}
 * </pre>
 * 
 * or throw an exception that is later transformed into a Shibboleth error code. In these cases the message part of the
 * exception must contain the error code (Shibboleth Event ID).
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class ExternalAutenticationErrorCodeException extends Exception {

  /** For serializing. */
  private static final long serialVersionUID = -4859301071999813267L;

  /** The error message. */
  private String actualMessage;

  /**
   * Constructor assigning the error event ID.
   * 
   * @param authnEventId
   *          the error event ID
   */
  public ExternalAutenticationErrorCodeException(String authnEventId) {
    super(authnEventId);
  }

  /**
   * Constructor assigning the error event ID and the textual error message.
   * 
   * @param authnEventId
   *          the error event ID
   * @param message
   *          the textual error message
   */
  public ExternalAutenticationErrorCodeException(String authnEventId, String message) {
    super(authnEventId);
    this.actualMessage = message;
  }

  /**
   * Constructor assigning the error event ID and the underlying cause.
   * 
   * @param authnEventId
   *          the error event ID
   * @param cause
   *          the cause of the error
   */
  public ExternalAutenticationErrorCodeException(String authnEventId, Throwable cause) {
    super(authnEventId, cause);
  }

  /**
   * Constructor assigning the error event ID, the textual error message and the underlying cause.
   * 
   * @param authnEventId
   *          the error event ID
   * @param message
   *          the textual error message
   * @param cause
   *          the cause of the error
   */
  public ExternalAutenticationErrorCodeException(String authnEventId, String message, Throwable cause) {
    super(authnEventId, cause);
    this.actualMessage = message;
  }

  /**
   * Returns the textual error message. {@link #getMessage()} will return the event ID.
   * 
   * @return the textual error message
   */
  public String getActualMessage() {
    return this.actualMessage;
  }

}
