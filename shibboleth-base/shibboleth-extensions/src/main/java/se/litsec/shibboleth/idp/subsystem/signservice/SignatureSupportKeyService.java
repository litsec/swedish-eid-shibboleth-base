/*
 * Copyright 2017-2021 Litsec AB
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
package se.litsec.shibboleth.idp.subsystem.signservice;

import java.io.IOException;
import java.security.SignatureException;

import org.opensaml.xmlsec.encryption.support.DecryptionException;

import net.shibboleth.utilities.java.support.component.IdentifiedComponent;
import net.shibboleth.utilities.java.support.component.InitializableComponent;
import net.shibboleth.utilities.java.support.component.UnmodifiableComponent;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SAD;

/**
 * A wrapper service handling operations for Signature Service support that involves access to IdP private key
 * operations (decryption and signing).
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public interface SignatureSupportKeyService extends InitializableComponent, IdentifiedComponent, UnmodifiableComponent {

  /**
   * Decrypts the encrypted message of a {@link SignMessage} and returns the cleartext {@code Message}.
   * 
   * @param signMessage
   *          the element holding the encrypted message
   * @return a cleartext {@code Message} element
   * @throws DecryptionException
   *           for decryption errors
   */
  Message decrypt(SignMessage signMessage) throws DecryptionException;

  /**
   * Based on the supplied Signature Activation Data ({@link SAD}) object, the method creates a SAD JWT and signs it.
   * 
   * @param sad
   *          the SAD to encode as a signed JWT
   * @return The encoded JWT
   * @throws SignatureException
   *           for signature errors
   * @throws IOException
   *           for JSON processing errors
   */
  String createSADJwt(SAD sad) throws SignatureException, IOException;

}
