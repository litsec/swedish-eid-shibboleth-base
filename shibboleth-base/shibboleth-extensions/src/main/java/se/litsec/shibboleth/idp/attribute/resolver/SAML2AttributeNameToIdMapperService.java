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
package se.litsec.shibboleth.idp.attribute.resolver;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.idp.attribute.transcoding.TranscodingRule;
import net.shibboleth.idp.attribute.transcoding.impl.TranscodingRuleLoader;
import net.shibboleth.idp.saml.attribute.transcoding.SAML2AttributeTranscoder;

/**
 * A service bean that maps between an SAML v2 attribute name and its corresponding Shibboleth attribute ID. This is
 * useful for external authentication implementations that only knows about the actual SAML attribute name and not its
 * Shibbleth ID.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class SAML2AttributeNameToIdMapperService implements ApplicationContextAware {

  /** The application context. */
  private ApplicationContext applicationContext;

  /** Cached attribute name to id mapping. */
  private Map<String, String> attributesMapping;

  /**
   * Returns the Shibboleth attribute ID that corresponds to the supplied SAML2 attribute name.
   * 
   * @param name
   *          the attribute name
   * @return the Shibboleth attribute ID or null if no mapping exists
   */
  public synchronized String getAttributeID(final String name) {    
    if (this.attributesMapping == null) {
      this.loadMappings();
    }
    return this.attributesMapping.get(name);
  }
  
  /** {@inheritDoc} */
  @Override
  public void setApplicationContext(final ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

  /**
   * Loads all attribute mappings for the system.
   */
  private void loadMappings() {
    if (this.attributesMapping != null) {
      // Already loaded ...
      return;
    }
    this.attributesMapping = new HashMap<>();
    
    final Collection<TranscodingRule> mappingBeans =
        this.applicationContext.getBeansOfType(TranscodingRule.class).values();
    final Collection<TranscodingRuleLoader> loaderBeans =
        this.applicationContext.getBeansOfType(TranscodingRuleLoader.class).values();

    final Collection<TranscodingRule> holder = new ArrayList<>();
    if (mappingBeans != null) {
      holder.addAll(mappingBeans);
    }
    if (loaderBeans != null) {
      loaderBeans.forEach(loader -> holder.addAll(loader.getRules()));
    }
    
    for (final TranscodingRule rule : holder) {
      final String samlName = rule.get(SAML2AttributeTranscoder.PROP_NAME, String.class);
      if (samlName != null) {
        final String id = rule.get(AttributeTranscoderRegistry.PROP_ID, String.class);
        this.attributesMapping.put(samlName, id);
      }
    }
  }
  
}
