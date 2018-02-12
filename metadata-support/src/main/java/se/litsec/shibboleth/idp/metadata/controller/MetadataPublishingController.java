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
package se.litsec.shibboleth.idp.metadata.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import se.litsec.opensaml.saml2.metadata.EntityDescriptorContainer;

/**
 * MVC controller for publishing signed, and up-to-date, SAML metadata.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@Controller
public class MetadataPublishingController extends AbstractMetadataPublishingController {

  /**
   * Constructor taking the container holding the metadata to publish.
   * 
   * @param metadataContainer
   *          the metadata to publish
   */  
  public MetadataPublishingController(EntityDescriptorContainer metadataContainer) {
    super(metadataContainer);
  }

  /** {@inheritDoc} */
  @RequestMapping(value = "/idp.xml", method = RequestMethod.GET)
  @ResponseBody
  public HttpEntity<byte[]> getMetadata(HttpServletRequest request, @RequestHeader(name = "Accept", required = false) String acceptHeader) {
    return super.getMetadata(request, acceptHeader);
  }

}
