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
package se.litsec.shibboleth.idp.metadata.support;

import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.ResourcePatternUtils;

import se.litsec.opensaml.utils.X509CertificateUtils;

/**
 * Utility factory bean that scans a directory for X.509 certificate resources and returns a list.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class X509CertificateListFromDirectoryFactoryBean extends AbstractFactoryBean<List<X509Certificate>> implements ResourceLoaderAware {

  /** Logging instance. */
  private Logger logger = LoggerFactory.getLogger(X509CertificateListFromDirectoryFactoryBean.class);

  /** The resource loader. */
  private ResourceLoader resourceLoader;

  /** The directory to scan for certificates. */
  private File directory;

  /**
   * Constructor taking the directory that should be scanned for certificates as an argument.
   * 
   * @param directory
   *          the directory to scan
   */
  public X509CertificateListFromDirectoryFactoryBean(String directory) throws IOException {
    File dir = new File(directory);
    if (dir.isDirectory()) {
      this.directory = dir;
    }
  }

  /** {@inheritDoc} */
  @Override
  protected List<X509Certificate> createInstance() throws Exception {
    if (this.directory == null) {
      logger.info("Directory {} does not exist - returning empty list");
      return Collections.emptyList();
    }
    Resource[] resources = ResourcePatternUtils.getResourcePatternResolver(resourceLoader).getResources("file:" + this.directory.getAbsolutePath() + "/*");
    List<X509Certificate> list = new ArrayList<>();
    for (Resource resource : resources) {
      if (resource.getFile().isDirectory()) {
        continue;
      }
      try {
        X509Certificate cert = X509CertificateUtils.decodeCertificate(resource.getFile());
        list.add(cert);
      }
      catch (Exception e) {
        logger.info("While scanning directory {} for certificates - failed to decode file '{}' - {}",
          this.directory, resource.getFilename(), e.getMessage());
      }
    }
    return list;
  }

  /** {@inheritDoc} */
  @Override
  public Class<?> getObjectType() {
    return List.class;
  }

  /** {@inheritDoc} */
  @Override
  public void setResourceLoader(ResourceLoader resourceLoader) {
    this.resourceLoader = resourceLoader;
  }

}
