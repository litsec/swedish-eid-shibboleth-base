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

import java.io.ByteArrayOutputStream;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import se.litsec.opensaml.saml2.metadata.EntityDescriptorContainer;

/**
 * MVC controller for publishing signed, and up-to-date, IdP metadata.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@Controller
public class MetadataPublishingController implements InitializingBean {

  /** Media type for SAML metadata in XML format. */
  public static final String APPLICATION_SAML_METADATA = "application/samlmetadata+xml";

  /** Logging instance. */
  private Logger logger = LoggerFactory.getLogger(MetadataPublishingController.class);

  /** Holds the SAML metadata to publish. */
  private EntityDescriptorContainer metadataContainer;

  /**
   * Returns the metadata for the entity.
   * 
   * @param request
   *          the HTTP request
   * @param acceptHeader
   *          the Accept header value
   * @return an HttpEntity holding the SAML metadata
   */
  @RequestMapping(value = "/metadata", method = RequestMethod.GET)
  @ResponseBody
  public HttpEntity<byte[]> getMetadata(HttpServletRequest request, @RequestHeader("Accept") String acceptHeader) {

    logger.debug("Request to download metadata from {}", request.getRemoteAddr());

    try {

      // Check if the metadata is up-to-date according to how the container was configured.
      //
      if (this.metadataContainer.updateRequired(true)) {
        logger.debug("Metadata needs to be updated ...");
        this.metadataContainer.update(true);
        logger.debug("Metadata was updated and signed");
      }
      else {
        logger.debug("Metadata is up-to-date, using cached metadata");
      }

      // Get the DOM for the metadata and serialize it.
      //
      Element dom = this.metadataContainer.marshall();

      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      SerializeSupport.writeNode(dom, stream);

      // Assign the HTTP headers.
      //
      HttpHeaders header = new HttpHeaders();
      if (acceptHeader != null && !acceptHeader.contains(APPLICATION_SAML_METADATA)) {
        header.setContentType(MediaType.APPLICATION_XML);
      }
      else {
        header.setContentType(MediaType.valueOf(APPLICATION_SAML_METADATA));
      }
      // TODO: turn off caching

      byte[] documentBody = stream.toByteArray();
      header.setContentLength(documentBody.length);
      return new HttpEntity<byte[]>(documentBody, header);
    }
    catch (SignatureException | MarshallingException e) {
      logger.error("Failed to return valid metadata", e);
      return new ResponseEntity<byte[]>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Assigns the container holding the metadata to publish.
   * 
   * @param metadataContainer
   *          the metadata to publish
   */
  public void setMetadataContainer(EntityDescriptorContainer metadataContainer) {
    this.metadataContainer = metadataContainer;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.metadataContainer, "Property 'metadataContainer' must not be null");
  }

}
