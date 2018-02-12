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

import net.shibboleth.ext.spring.service.AbstractServiceableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import se.litsec.swedisheid.opensaml.saml2.signservice.SignMessageDecrypter;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.Message;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessage;

/**
 * A wrapper for {@link SignMessageDecrypter} implementing the {@link SignMessageDecryptionService} interface for use in
 * a reloadable Spring subsystem.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class ReloadingSignMessageDecryptionService extends AbstractServiceableComponent<SignMessageDecryptionService> implements SignMessageDecryptionService {

  /** Fixed ID for this component. */
  public static final String ID = "sign-message-decrypter";
  
  /** The decrypter instance. */
  private SignMessageDecrypter signMessageDecrypter;

  /**
   * Constructor.
   * 
   * @param signMessageDecrypter
   *          the decrypter instance
   */
  public ReloadingSignMessageDecryptionService(SignMessageDecrypter signMessageDecrypter) {
    this.signMessageDecrypter = signMessageDecrypter;
  }

  /** {@inheritDoc} */
  @Override
  public Message decrypt(SignMessage signMessage) throws DecryptionException {
    return this.signMessageDecrypter.decrypt(signMessage);
  }

  /** {@inheritDoc} */
  @Override
  public SignMessageDecryptionService getComponent() {
    return this;
  }
  
  /** {@inheritDoc} */
  @Override
  protected void doInitialize() throws ComponentInitializationException {
      this.setId(ID);
      super.doInitialize();
  }  

}
