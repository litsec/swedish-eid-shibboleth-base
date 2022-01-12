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
package se.litsec.shibboleth.idp.metadata.controller;

import java.io.ByteArrayOutputStream;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;

/**
 * MVC controller for publishing signed, and up-to-date, SAML metadata.
 * <p>
 * Note: The class is abstract since there may be the need to instantiate several controllers for different entities
 * within the same system. Therefore, the implementing classes will have to add the {@code Controller} and
 * {@code RequestMapping} annotations.
 * </p>
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public abstract class AbstractMetadataPublishingController {

  /** Media type for SAML metadata in XML format. */
  public static final String APPLICATION_SAML_METADATA = "application/samlmetadata+xml";

  /** Logging instance. */
  private Logger logger = LoggerFactory.getLogger(MetadataPublishingController.class);

  /** Holds the SAML metadata to publish. */
  private EntityDescriptorContainer metadataContainer;

  /**
   * Constructor taking the container holding the metadata to publish.
   * 
   * @param metadataContainer
   *          the metadata to publish
   */
  public AbstractMetadataPublishingController(EntityDescriptorContainer metadataContainer) {
    this.metadataContainer = metadataContainer;
  }
  
  /**
   * Returns the metadata for the entity.
   * 
   * @param request
   *          the HTTP request
   * @param acceptHeader
   *          the Accept header value
   * @return an HttpEntity holding the SAML metadata
   */
  public HttpEntity<byte[]> getMetadata(HttpServletRequest request, @RequestHeader(name = "Accept", required = false) String acceptHeader) {

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

}
