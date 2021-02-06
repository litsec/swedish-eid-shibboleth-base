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

import java.time.Instant;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.attribute.resolver.AttributeResolver;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.idp.attribute.transcoding.impl.AttributeRegistryServiceStrategy;
//import net.shibboleth.idp.saml.attribute.encoding.SAML2AttributeEncoder;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.service.ReloadableService;

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

  /** Service used to get the resolver used to fetch attributes. */
  private final ReloadableService<AttributeTranscoderRegistry> attributeRegistryService;
  
  //AttributeRegistryServiceStrategy j;
  
  /**
   * Whether the last invocation of {@link ReloadableService#reload()} on {@link #attributeResolverService} failed. This
   * limits the noise in log file.
   */
  @Nonnull private boolean captiveServiceReloadFailed;

  /** Cached attribute name to id mapping. */
  private Map<String, String> attributesMapping;

  /** Date when the cache was last refreshed. */
  @Nullable private Instant lastReload;

  /**
   * Constructor.
   * 
   * @param attributeRegistryService
   *          the service for the attribute registry we are to derive mapping info from
   */
  public SAML2AttributeNameToIdMapperService(final ReloadableService<AttributeTranscoderRegistry> attributeRegistryService) {
    this.attributeRegistryService = Constraint.isNotNull(attributeRegistryService, "AttributRegistry cannot be null");
  }

  /**
   * Returns the Shibboleth attribute ID that corresponds to the supplied SAML2 attribute name.
   * 
   * @param name
   *          the attribute name
   * @return the Shibboleth attribute ID or {@code null} if no mapping exists
   */
  public String getAttributeID(String name) {
    Map<String, String> m = this.getMapping();
    return m != null ? m.get(name) : null;
  }

  /**
   * Returns the mapping between attribute names and their Shibboleth ID:s.
   * 
   * @return a mapping
   */
  private Map<String, String> getMapping() {
    if (this.attributesMapping != null && this.lastReload != null && this.lastReload.equals(this.attributeRegistryService
      .getLastSuccessfulReloadInstant())) {
      return this.attributesMapping;
    }
//    // Reload.
//    ServiceableComponent<AttributeResolver> component = null;
//    Map<String, String> am = null;
//    try {
//      // Get date before we get the component. That way we'll not leak changes.
//      final Instant when = this.attributeResolverService.getLastSuccessfulReloadInstant();
//      component = this.attributeResolverService.getServiceableComponent();
//      if (null == component) {
//        if (!captiveServiceReloadFailed) {
//          logger.error("Invalid AttributeResolver configuration");
//        }
//        captiveServiceReloadFailed = true;
//      }
//      else {
//        final AttributeResolver attributeResolver = component.getComponent();
//        am = new HashMap<>();
//
//        Map<String, AttributeDefinition> map = attributeResolver.getAttributeDefinitions();
//        for (Map.Entry<String, AttributeDefinition> entry : map.entrySet()) {
//          String name = null;
//          Set<AttributeEncoder<?>> encoders = entry.getValue().getAttributeEncoders();
//          for (AttributeEncoder<?> encoder : encoders) {
//            if (encoder instanceof SAML2AttributeEncoder) {
//              name = ((SAML2AttributeEncoder<?>) encoder).getName();
//              if (name != null) {
//                break;
//              }
//            }
//          }
//          if (name != null) {
//            logger.debug("Adding mapping between SAML2 attribute '{}' and id '{}'", name, entry.getKey());
//            am.put(name, entry.getKey());
//          }
//          else {
//            logger.debug("No mapping to SAML2 attribute for attribute id '{}'", entry.getKey());
//          }
//        }
//
//        this.captiveServiceReloadFailed = false;
//        this.lastReload = when;
//      }
//    }
//    finally {
//      if (null != component) {
//        component.unpinComponent();
//      }
//    }
//
//    this.attributesMapping = am;
//    return am;
    
    return null;
  }

}
