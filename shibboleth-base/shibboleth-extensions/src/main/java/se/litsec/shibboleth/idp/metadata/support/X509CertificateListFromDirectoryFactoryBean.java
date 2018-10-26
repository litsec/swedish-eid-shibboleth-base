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
   * @throws IOException
   *           for IO errors
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
    Resource[] resources = ResourcePatternUtils.getResourcePatternResolver(resourceLoader).getResources("file:" + this.directory
      .getAbsolutePath() + "/*");
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
