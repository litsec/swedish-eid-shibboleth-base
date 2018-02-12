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
