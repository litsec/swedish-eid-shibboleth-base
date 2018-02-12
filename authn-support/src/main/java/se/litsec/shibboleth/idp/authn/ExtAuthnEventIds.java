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

import net.shibboleth.idp.authn.AuthnEventIds;

/**
 * Shibboleth defines the class {@link AuthnEventIds} that holds constants for events used in Shibboleth's Spring Web
 * Flow definitions. This class extends these constants with the events defined in the Swedish eID Shibboleth base
 * package.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 * @see AuthnEventIds
 */
public class ExtAuthnEventIds {

  /**
   * ID of event returned if the end user cancels an authentication process.
   */
  public static final String CANCEL_AUTHN = "CancelAuthn";
  
  /**
   * ID of event returned if the authentication process is terminated due to a detected fraud attempt.
   */
  public static final String FRAUD = "Fraud";
  
  /**
   * ID of event returned if the authentication process is terminated due to a possible (or suspected) fraud attempt.
   */
  public static final String POSSIBLE_FRAUD = "PossibleFraud";
  
  /**
   * ID that signals that the IdP failed to decrypt an encrypted SignMessage.
   */
  public static final String SIGN_MESSAGE_DECRYPTION_ERROR = "SignMessageDecryptionError";
  
  /**
   * ID that signals that the IdP does not support the given MIME type of a SignMessage.
   */
  public static final String SIGN_MESSAGE_TYPE_NOT_SUPPORTED = "SignMessageTypeNotSupported";

}
