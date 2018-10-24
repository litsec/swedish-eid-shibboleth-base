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

import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.core.io.DefaultResourceLoader;

/**
 * Test cases for {@link X509CertificateListFromDirectoryFactoryBean}.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class X509CertificateListFromDirectoryFactoryBeanTest {

  @Test
  public void testScan() throws Exception {
    
    X509CertificateListFromDirectoryFactoryBean bean = new X509CertificateListFromDirectoryFactoryBean("src/test/resources/certtest");
    bean.setResourceLoader(new DefaultResourceLoader());
    bean.afterPropertiesSet();
    
    List<X509Certificate> list = bean.getObject();
    Assert.assertTrue(list.size() == 2);
  }
  
  @Test
  public void testEmpty() throws Exception {
    X509CertificateListFromDirectoryFactoryBean bean = new X509CertificateListFromDirectoryFactoryBean("src/test/resources/certtest/empty");
    bean.setResourceLoader(new DefaultResourceLoader());
    bean.afterPropertiesSet();
    
    List<X509Certificate> list = bean.getObject();
    Assert.assertTrue(list.isEmpty());
  }
  
  @Test
  public void testNotExists() throws Exception {
    X509CertificateListFromDirectoryFactoryBean bean = new X509CertificateListFromDirectoryFactoryBean("src/test/resources/certtest/notthere");
    bean.setResourceLoader(new DefaultResourceLoader());
    bean.afterPropertiesSet();
    
    List<X509Certificate> list = bean.getObject();
    Assert.assertTrue(list.isEmpty());
  }

}
