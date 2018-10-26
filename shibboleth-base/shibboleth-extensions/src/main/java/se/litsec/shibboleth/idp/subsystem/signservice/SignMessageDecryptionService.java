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
package se.litsec.shibboleth.idp.subsystem.signservice;

import org.opensaml.xmlsec.encryption.support.DecryptionException;

import net.shibboleth.utilities.java.support.component.IdentifiedComponent;
import net.shibboleth.utilities.java.support.component.InitializableComponent;
import net.shibboleth.utilities.java.support.component.UnmodifiableComponent;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.Message;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessage;

/**
 * A wrapper service for handling decryption of sign messages.
 * 
 * @deprecated As of version 1.2, replaced by {@link SignatureSupportKeyService}
 */
@Deprecated
public interface SignMessageDecryptionService extends InitializableComponent, IdentifiedComponent, UnmodifiableComponent {

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

}
