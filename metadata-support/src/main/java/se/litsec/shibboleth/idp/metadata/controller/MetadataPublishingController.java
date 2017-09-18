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
  public HttpEntity<byte[]> getMetadata(HttpServletRequest request, @RequestHeader("Accept") String acceptHeader) {
    return super.getMetadata(request, acceptHeader);
  }

}
