/*
 * Copyright 2017-2019 Litsec AB
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
package se.litsec.shibboleth.idp.config;

import org.opensaml.core.config.InitializationException;

import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;
import se.swedenconnect.opensaml.xmlsec.config.SecurityConfiguration;

/**
 * A bean that accepts a {@link SecurityConfiguration} object and applies it to the OpenSAML configuration service to
 * set algorithm defaults.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class DefaultSecurityConfigurationBean extends AbstractInitializableComponent {

  /** The security configuration to apply. */
  private SecurityConfiguration securityConfiguration;

  /**
   * Constructor assigning the security configuration to apply.
   * 
   * @param securityConfiguration
   *          security configuration
   */
  public DefaultSecurityConfigurationBean(SecurityConfiguration securityConfiguration) {
    this.securityConfiguration = Constraint.isNotNull(securityConfiguration, "securityConfiguration must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doInitialize() throws ComponentInitializationException {
    try {
      this.securityConfiguration.initOpenSAML();
    }
    catch (InitializationException e) {
      throw new ComponentInitializationException("Failed to apply default OpenSAML security configuration", e);
    }
  }

}
