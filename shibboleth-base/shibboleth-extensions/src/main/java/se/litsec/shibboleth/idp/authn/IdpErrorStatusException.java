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

import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;

import net.shibboleth.idp.authn.AuthnEventIds;
import se.litsec.opensaml.utils.ObjectUtils;

/**
 * Exception that Proxy IdP:s may use to signal errors received from the SP-part, or by "ordinary" IdP:s to signal a
 * detailed error.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class IdpErrorStatusException extends ExternalAutenticationErrorCodeException {

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
    super(AuthnEventIds.AUTHN_EXCEPTION);
    this.status = status;
  }

  /**
   * Constructor accepting a status object and an error event ID.
   * 
   * @param status
   *          the error status
   * @param authnEventId
   *          the error event ID
   */
  public IdpErrorStatusException(Status status, String authnEventId) {
    super(authnEventId);
    this.status = status;
  }

  /**
   * Constructor accepting a status object and an error event ID.
   * 
   * @param status
   *          the error status
   * @param authnEventId
   *          the error event ID
   * @param message
   *          the textual error message
   */
  public IdpErrorStatusException(Status status, String authnEventId, String message) {
    super(authnEventId, message);
    this.status = status;
  }

  /**
   * Constructor accepting an error event ID and the parts of a status object.
   * 
   * @param authnEventId
   *          the error event ID
   * @param statusCode
   *          the main status code
   * @param subStatusCode
   *          the sub status code
   * @param message
   *          the textual error message
   */
  public IdpErrorStatusException(String authnEventId, String statusCode, String subStatusCode, String message) {
    super(authnEventId, message);
    this.status = getStatusBuilder(statusCode).subStatusCode(subStatusCode).statusMessage(message).build();
  }

  /**
   * Returns the error status object
   * 
   * @return the status object
   */
  public Status getStatus() {
    return this.status;
  }

  /**
   * Returns a builder for a shorter way of creating a basic Status object.
   * 
   * @param code
   *          the main status code
   * @return a status builder
   */
  public static StatusBuilder getStatusBuilder(String code) {
    return new StatusBuilder(code);
  }

  public static class StatusBuilder {

    private String statusCode;
    private String subStatusCode;
    private String statusMessage;

    public StatusBuilder(String statusCode) {
      this.statusCode = statusCode;
    }

    public Status build() {
      Status status = ObjectUtils.createSamlObject(Status.class);

      StatusCode sc = ObjectUtils.createSamlObject(StatusCode.class);
      sc.setValue(this.statusCode);

      if (subStatusCode != null) {
        StatusCode ssc = ObjectUtils.createSamlObject(StatusCode.class);
        ssc.setValue(this.subStatusCode);
        sc.setStatusCode(ssc);
      }
      status.setStatusCode(sc);
      if (statusMessage != null) {
        StatusMessage sm = ObjectUtils.createSamlObject(StatusMessage.class);
        sm.setMessage(this.statusMessage);
        status.setStatusMessage(sm);
      }
      return status;
    }

    public StatusBuilder subStatusCode(String code) {
      this.subStatusCode = code;
      return this;
    }

    public StatusBuilder statusMessage(String message) {
      this.statusMessage = message;
      return this;
    }

  }

}
