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
