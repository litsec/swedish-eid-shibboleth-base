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
