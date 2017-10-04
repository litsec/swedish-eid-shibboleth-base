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
package se.litsec.shibboleth.idp.authn.context;

import org.opensaml.messaging.context.BaseContext;

import se.litsec.swedisheid.opensaml.saml2.signservice.dss.Message;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessage;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessageMimeTypeEnum;

/**
 * An IdP for the Swedish eID Framework may receive a {@code SignMessage} extension indicating that a Signature Service
 * requests the IdP to display a message to the user. This context stores
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class SignMessageContext extends BaseContext {

  /** The SignMessage. */
  private SignMessage signMessage;

  /** The cleartext message. */
  private Message clearTextMessage;
  
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

}
