package se.litsec.shibboleth.idp.attribute.resolver;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.resolver.AttributeDefinition;
import net.shibboleth.idp.attribute.resolver.AttributeResolver;
import net.shibboleth.idp.saml.attribute.encoding.SAML2AttributeEncoder;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.service.ReloadableService;
import net.shibboleth.utilities.java.support.service.ServiceableComponent;

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
  private final ReloadableService<AttributeResolver> attributeResolverService;

  /**
   * Whether the last invocation of {@link ReloadableService#reload()} on {@link #attributeResolverService} failed. This
   * limits the noise in log file.
   */
  @Nonnull private boolean captiveServiceReloadFailed;

  /** Cached attribute name to id mapping. */
  private Map<String, String> attributesMapping;

  /** Date when the cache was last refreshed. */
  @Nullable private DateTime lastReload;

  /**
   * Constructor.
   * 
   * @param resolverService
   *          the service for the attribute resolver we are to derive mapping info from
   */
  public SAML2AttributeNameToIdMapperService(final ReloadableService<AttributeResolver> resolverService) {
    attributeResolverService = Constraint.isNotNull(resolverService, "AttributeResolver cannot be null");
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
    if (this.attributesMapping != null && this.lastReload != null && this.lastReload.equals(this.attributeResolverService
      .getLastSuccessfulReloadInstant())) {
      return this.attributesMapping;
    }
    // Reload.
    ServiceableComponent<AttributeResolver> component = null;
    Map<String, String> am = null;
    try {
      // Get date before we get the component. That way we'll not leak changes.
      final DateTime when = this.attributeResolverService.getLastSuccessfulReloadInstant();
      component = this.attributeResolverService.getServiceableComponent();
      if (null == component) {
        if (!captiveServiceReloadFailed) {
          logger.error("Invalid AttributeResolver configuration");
        }
        captiveServiceReloadFailed = true;
      }
      else {
        final AttributeResolver attributeResolver = component.getComponent();
        am = new HashMap<>();

        Map<String, AttributeDefinition> map = attributeResolver.getAttributeDefinitions();
        for (Map.Entry<String, AttributeDefinition> entry : map.entrySet()) {
          String name = null;
          Set<AttributeEncoder<?>> encoders = entry.getValue().getAttributeEncoders();
          for (AttributeEncoder<?> encoder : encoders) {
            if (encoder instanceof SAML2AttributeEncoder) {
              name = ((SAML2AttributeEncoder<?>) encoder).getName();
              if (name != null) {
                break;
              }
            }
          }
          if (name != null) {
            logger.debug("Adding mapping between SAML2 attribute '{}' and id '{}'", name, entry.getKey());
            am.put(name, entry.getKey());
          }
          else {
            logger.debug("No mapping to SAML2 attribute for attribute id '{}'", entry.getKey());
          }
        }

        captiveServiceReloadFailed = false;
        lastReload = when;
      }
    }
    finally {
      if (null != component) {
        component.unpinComponent();
      }
    }

    this.attributesMapping = am;
    return am;
  }

}
