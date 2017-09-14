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

import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.service.ReloadableService;
import net.shibboleth.utilities.java.support.service.ServiceableComponent;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.Message;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessage;

/**
 * This class uses the {@link ReloadableService} concept to implement {@link SignMessageDecryptionService} to hide the
 * details of pinning and unpinning the underlying service.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class DelegatingSignMessageDecryptionService extends AbstractInitializableComponent implements SignMessageDecryptionService {

  /** The service which manages the reloading. */
  private final ReloadableService<SignMessageDecryptionService> service;

  /**
   * Constructor.
   * 
   * @param service
   *          the service which will manage the loading
   */
  public DelegatingSignMessageDecryptionService(ReloadableService<SignMessageDecryptionService> service) {
    this.service = Constraint.isNotNull(service, "SignMessageDecryptionService cannot be null");
  }

  /** {@inheritDoc} */
  @Override
  public Message decrypt(SignMessage signMessage) throws DecryptionException {
    ServiceableComponent<SignMessageDecryptionService> component = null;
    try {
      component = service.getServiceableComponent();
      if (null == component) {
        throw new DecryptionException("SignMessageDecryptionService: Error accessing underlying component: Invalid configuration");
      }
      else {
        final SignMessageDecryptionService svc = component.getComponent();
        return svc.decrypt(signMessage);
      }
    }
    finally {
      if (null != component) {
        component.unpinComponent();
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isInitialized() {
    return true;
  }

  /** {@inheritDoc} */
  @Override
  public String getId() {
    return ReloadingSignMessageDecryptionService.ID;
  }

}
