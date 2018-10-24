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
package se.litsec.shibboleth.idp.authn.context;

import org.opensaml.messaging.context.BaseContext;

import se.litsec.swedisheid.opensaml.saml2.signservice.dss.Message;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessage;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessageMimeTypeEnum;

/**
 * An IdP for the Swedish eID Framework may receive a {@code SignMessage} extension indicating that a Signature Service
 * requests the IdP to display a message to the user.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class SignMessageContext extends BaseContext {

  /** The SignMessage. */
  private SignMessage signMessage;

  /** The cleartext message. */
  private Message clearTextMessage;

  /**
   * The message to display. Depending on whether processing of the clear text message was performed, this may not be
   * exactly the same as {@link #getClearTextMessage()}.
   */
  private String messageToDisplay;

  /** Flag telling whether the IdP should display the message. */
  private boolean doDisplayMessage = true;

  /**
   * Constructor.
   * 
   * @param signMessage
   *          the sign message
   */
  public SignMessageContext(SignMessage signMessage) {
    this.signMessage = signMessage;
    if (this.signMessage.getMessage() != null) {
      this.clearTextMessage = this.signMessage.getMessage();
    }
  }

  /**
   * Returns the {@code SignMessage}.
   * 
   * @return the {@code SignMessage}
   */
  public SignMessage getSignMessage() {
    return this.signMessage;
  }

  /**
   * Returns the cleartext message in its Base64-decoded form.
   * 
   * @return the message
   */
  public String getClearTextMessage() {
    if (this.clearTextMessage != null) {
      return this.clearTextMessage.getContent();
    }
    return null;
  }

  /**
   * Assigns the cleartext message (after decrypting).
   * 
   * @param clearTextMessage
   *          the message
   */
  public void setClearTextMessage(Message clearTextMessage) {
    this.clearTextMessage = clearTextMessage;
  }

  /**
   * Returns the message to display. Depending on whether processing of the clear text message was performed, this may
   * not be exactly the same as {@link #getClearTextMessage()}.
   * 
   * @return the message to display
   */
  public String getMessageToDisplay() {
    if (this.messageToDisplay == null) {
      return this.getClearTextMessage();
    }
    return this.messageToDisplay;
  }

  /**
   * If a processing of the cleartext message is performed, the processed message should be assigned using this method.
   * 
   * @param messageToDisplay
   *          the message to display
   */
  public void setMessageToDisplay(String messageToDisplay) {
    this.messageToDisplay = messageToDisplay;
  }

  /**
   * Tells whether the {@code MustShow} attribute is set or not.
   * 
   * @return the {@code MustShow} attribute
   */
  public boolean mustShow() {
    return this.signMessage.isMustShow();
  }

  /**
   * Returns the MIME type for the message to display.
   * 
   * @return the MIME type
   */
  public SignMessageMimeTypeEnum getMimeType() {
    return this.signMessage.getMimeType() != null ? this.signMessage.getMimeTypeEnum() : SignMessageMimeTypeEnum.TEXT;
  }

  /**
   * Predicate telling whether the message should be displayed by the IdP.
   * 
   * @return {@code true} if the message should be displayed, and {@code false} otherwise
   */
  public boolean isDoDisplayMessage() {
    return this.doDisplayMessage;
  }

  /**
   * Assigns whether the message should be displayed by the IdP.
   * 
   * @param displayMessage
   *          {@code true} if the message should be displayed, and {@code false} otherwise
   */
  public void setDoDisplayMessage(boolean displayMessage) {
    this.doDisplayMessage = displayMessage;
  }

}
