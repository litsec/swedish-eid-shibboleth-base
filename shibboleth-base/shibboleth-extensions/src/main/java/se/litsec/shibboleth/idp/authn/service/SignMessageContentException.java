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
package se.litsec.shibboleth.idp.authn.service;

/**
 * Exception class for indicating that the format/contents of a supplied sign message is not valid.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class SignMessageContentException extends Exception {

  /** For serialization. */
  private static final long serialVersionUID = -5069997077986405595L;

  /**
   * Constructor.
   * 
   * @param message
   *          the error message
   */
  public SignMessageContentException(String message) {
    super(message);
  }

  /**
   * Constructor.
   * 
   * @param message
   *          the error message
   * @param cause
   *          the cause of the error
   */
  public SignMessageContentException(String message, Throwable cause) {
    super(message, cause);
  }

}
