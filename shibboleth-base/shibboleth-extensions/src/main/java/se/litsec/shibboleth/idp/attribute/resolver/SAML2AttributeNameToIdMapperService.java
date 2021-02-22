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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.saml.saml2.core.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.idp.attribute.transcoding.TranscodingRule;
import net.shibboleth.utilities.java.support.service.ReloadableService;
import net.shibboleth.utilities.java.support.service.ServiceableComponent;
import se.litsec.opensaml.saml2.attribute.AttributeBuilder;

/**
 * A service bean that maps between an SAML v2 attribute name and its corresponding Shibboleth attribute ID. This is
 * useful for external authentication implementations that only knows about the actual SAML attribute name and not its
 * Shibbleth ID.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class SAML2AttributeNameToIdMapperService {
  
  /** Class logger. */
  private final Logger logger = LoggerFactory.getLogger(SAML2AttributeNameToIdMapperService.class);  

  /** Service used to get the mappings from. */
  private final ReloadableService<AttributeTranscoderRegistry> attributeRegistryService;
  
  /** Cached attribute name to id mapping. */
  private Map<String, String> attributesMapping = new HashMap<>();
  
  /**
   * Constructor.
   * 
   * @param attributeRegistryService service used to get the mappings from
   */
  public SAML2AttributeNameToIdMapperService(final ReloadableService<AttributeTranscoderRegistry> attributeRegistryService) {
    this.attributeRegistryService = attributeRegistryService;
  }  
  
  public synchronized String getAttributeID(final Attribute attribute) {
    if (this.attributesMapping.containsKey(attribute.getName())) {
      return this.attributesMapping.get(attribute.getName());
    }
    final String mapping = this.getMapping(attribute);
    this.attributesMapping.put(attribute.getName(), mapping);    
    return mapping;
  }
  
  public synchronized String getAttributeID(final String attributeName) {
    return this.getAttributeID(AttributeBuilder.builder(attributeName).value("dummy").build());
  }
  
  
  private String getMapping(final Attribute attribute) {

    ServiceableComponent<AttributeTranscoderRegistry> component = null;
    try {
      // Get date before we get the component. That way we'll not leak changes.
      component = this.attributeRegistryService.getServiceableComponent();
      if (null == component) {
        logger.error("Invalid AttributeRegistry configuration");
        return null;
      }
      else {
        final AttributeTranscoderRegistry attributeRegistry = component.getComponent();
        
        Collection<TranscodingRule> rules = attributeRegistry.getTranscodingRules(attribute);
        if (rules.isEmpty()) {
          logger.debug("No mapping to IdP attribute for attribute name '{}'", attribute.getName());
          return null;
        }
        
        return rules.iterator().next().get(AttributeTranscoderRegistry.PROP_ID, String.class);
      }
    }
    finally {
      if (null != component) {
        component.unpinComponent();
      }
    }
  }
  
}
