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

import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;

import se.swedenconnect.opensaml.xmlsec.config.AbstractSecurityConfiguration;

/**
 * A Security configuration that delivers exactly the same settings as {@link DefaultSecurityConfigurationBootstrap}.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class OpenSAMLSecurityConfiguration extends AbstractSecurityConfiguration {

  /** {@inheritDoc} */
  @Override
  public String getProfileName() {
    return "opensaml";
  }

}
