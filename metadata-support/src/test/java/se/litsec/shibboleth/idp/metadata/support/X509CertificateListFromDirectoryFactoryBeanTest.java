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
