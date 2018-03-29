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
package se.litsec.shibboleth.idp.authn.service.impl;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import se.litsec.opensaml.saml2.attribute.AttributeUtils;
import se.litsec.shibboleth.idp.authn.ExtAuthnEventIds;
import se.litsec.shibboleth.idp.authn.ExternalAutenticationErrorCodeException;
import se.litsec.shibboleth.idp.authn.context.AuthnContextClassContext;
import se.litsec.shibboleth.idp.authn.context.SignMessageContext;
import se.litsec.shibboleth.idp.authn.context.SignatureActivationDataContext;
import se.litsec.shibboleth.idp.authn.context.strategy.SignMessageContextLookup;
import se.litsec.shibboleth.idp.authn.context.strategy.SignatureActivationDataContextLookup;
import se.litsec.shibboleth.idp.authn.service.AuthnContextService;
import se.litsec.shibboleth.idp.authn.service.SignSupportService;
import se.litsec.shibboleth.idp.subsystem.signservice.SignatureSupportKeyService;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI.LoaEnum;
import se.litsec.swedisheid.opensaml.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.litsec.swedisheid.opensaml.saml2.metadata.entitycategory.EntityCategoryMetadataHelper;
import se.litsec.swedisheid.opensaml.saml2.signservice.SADFactory;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.Message;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessage;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessageMimeTypeEnum;
import se.litsec.swedisheid.opensaml.saml2.signservice.sap.SAD;
import se.litsec.swedisheid.opensaml.saml2.signservice.sap.SADRequest;
import se.litsec.swedisheid.opensaml.saml2.signservice.sap.SADVersion;

/**
 * Implementation of the {@link SignSupportService} interface.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class SignSupportServiceImpl extends AbstractAuthenticationBaseService implements SignSupportService, InitializingBean {

  /** Logging instance. */
  private final Logger log = LoggerFactory.getLogger(SignSupportServiceImpl.class);

  /** Strategy used to locate the SignMessageContext. */
  @SuppressWarnings("rawtypes")
  protected static Function<ProfileRequestContext, SignMessageContext> signMessageContextLookupStrategy = Functions
    .compose(new SignMessageContextLookup(), authenticationContextLookupStrategy);

  /** Strategy used to locate the SignatureActivationDataContext. */
  @SuppressWarnings("rawtypes")
  protected static Function<ProfileRequestContext, SignatureActivationDataContext> sadContextLookupStrategy = Functions
    .compose(new SignatureActivationDataContextLookup(), authenticationContextLookupStrategy);

  /** The AuthnContext service that helps us checking whether a request is valid. */
  protected AuthnContextService authnContextService;

  /** The SignatureSupportKey service. */
  protected SignatureSupportKeyService signatureSupportKeyService;

  /** The entityID of this IdP instance. */
  protected String entityID;

  /** The supported MIME types (if {@code null} all are supported). */
  protected List<String> supportedMimeTypes;

  /** Indicates whether this instance supports SCAL2 - default is false. */
  protected boolean scal2Supported = false;

  /** The factory for creating SAD:s. */
  protected SADFactory sadFactory;

  /** The SAD versions supported by the IdP. */
  protected static final List<SADVersion> supportedSadVersions = Arrays.asList(SADVersion.valueOf("1.0"));

  /** {@inheritDoc} */
  @Override
  public void initializeContext(ProfileRequestContext<?, ?> context) throws ExternalAutenticationErrorCodeException {

    final String logId = this.getLogString(context);

    AuthnRequest authnRequest = this.getAuthnRequest(context);
    if (authnRequest == null) {
      log.error("No AuthnRequest available [{}]", logId);
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.INVALID_AUTHN_CTX, "Missing AuthnRequest");
    }
    if (authnRequest.getExtensions() != null) {
      SignMessage signMessage = authnRequest.getExtensions()
        .getUnknownXMLObjects()
        .stream()
        .filter(SignMessage.class::isInstance)
        .map(SignMessage.class::cast)
        .findFirst()
        .orElse(null);

      if (signMessage != null) {
        log.debug("AuthnContext contains SignMessage extension, creating SignMessageContext ... [{}]", logId);
        this.getAuthenticationContext(context).addSubcontext(new SignMessageContext(signMessage), true);
      }

      SADRequest sadRequest = authnRequest.getExtensions()
        .getUnknownXMLObjects()
        .stream()
        .filter(SADRequest.class::isInstance)
        .map(SADRequest.class::cast)
        .findFirst()
        .orElse(null);

      if (sadRequest != null) {
        if (this.supportsScal2()) {
          log.debug("AuthnContext contains SADRequest extension, creating SignatureActivationDataContext ... [{}]", logId);
          this.getAuthenticationContext(context).addSubcontext(new SignatureActivationDataContext(sadRequest), true);
        }
        else {
          log.info("AuthnContext contains SADRequest extension, but SCAL2 (SAD generation) is not supported, ignoring ... [{}]", logId);
        }
      }
    }
  }

  /**
   * If a {@code SignMessage} exists the method will decrypt it (if needed).
   */
  @Override
  public void processRequest(ProfileRequestContext<?, ?> context) throws ExternalAutenticationErrorCodeException {
    final String logId = this.getLogString(context);
    boolean isSignatureService = this.isSignatureServicePeer(context);

    SignMessageContext signMessageContext = this.getSignMessageContext(context);
    if (signMessageContext == null) {

      // If the peer is a signature service and has only requested a sigmessage LoA we report an error.
      //
      if (isSignatureService) {
        AuthnContextClassContext authnContextClassContext = this.authnContextService.getAuthnContextClassContext(context);
        for (String loa : authnContextClassContext.getAuthnContextClassRefs()) {
          if (this.isSignMessageURI(loa)) {
            log.info("SP has requested '{}' but did not include SignMessage, removing ... [{}]", loa, logId);
            authnContextClassContext.deleteAuthnContextClassRef(loa);
          }
        }
        if (authnContextClassContext.isEmpty()) {
          final String msg = "No valid AuthnContext URI:s were specified in AuthnRequest";
          log.info("{} - can not proceed [{}]", msg, logId);
          throw new ExternalAutenticationErrorCodeException(AuthnEventIds.REQUEST_UNSUPPORTED, msg);
        }
      }
    }
    else {
      // If an ordinary SP included a SignMessage in the request, we simply ignore it.
      //
      if (!isSignatureService) {
        log.warn("Requesting SP is not a signature service, but included SignMessage extension, ignoring ... [{}]", logId);
        AuthenticationContext authnContext = this.getAuthenticationContext(context);
        authnContext.removeSubcontext(SignMessageContext.class);
      }
      // Else, make additional checks and decrypt.
      //
      else {

        // Decrypt the message
        //
        if (signMessageContext.getSignMessage().getEncryptedMessage() != null) {
          try {
            Message cleartextMessage = this.signatureSupportKeyService.decrypt(signMessageContext.getSignMessage());
            log.debug("SignMessage was successfully decrypted [{}]", logId);
            signMessageContext.setClearTextMessage(cleartextMessage);
          }
          catch (DecryptionException e) {
            final String msg = String.format("Failed to decrypt SignMessage - %s", e.getMessage());
            log.error("{} [{}]", msg, logId);
            throw new ExternalAutenticationErrorCodeException(ExtAuthnEventIds.SIGN_MESSAGE_DECRYPTION_ERROR, msg);
          }
        }
        else {
          log.debug("SignMessage was not encrypted [{}]", logId);
        }

        if (!this.supportsMimeType(signMessageContext.getMimeType())) {
          log.warn("IdP does not support display of SignMessage with type '{}' [{}]", signMessageContext.getMimeType(), logId);
          signMessageContext.setDisplayMessage(false);

          if (signMessageContext.mustShow()) {
            throw new ExternalAutenticationErrorCodeException(ExtAuthnEventIds.SIGN_MESSAGE_TYPE_NOT_SUPPORTED,
              "Unsupported SignMessage mime type");
          }
        }
        
        // Sanity check - If the clear text message is empty, we can not display anything.
        //
        if (signMessageContext.getClearTextMessage() == null || signMessageContext.getClearTextMessage().matches("\\s*")) {           
          log.warn("Sign message is empty or contains only non-visible characters [{}]", logId);
          signMessageContext.setDisplayMessage(false);
          
          if (signMessageContext.mustShow()) {
            throw new ExternalAutenticationErrorCodeException(AuthnEventIds.REQUEST_UNSUPPORTED, "No sign message to show");
          }
        }
        
        // If the SignMessage element from the signature request includes a MustShow attribute with the value true, the
        // Signature Service MUST require that the provided sign message is displayed by the Identity Provider, by
        // including a sigmessage authentication context URI.
        //
        if (signMessageContext.mustShow()) {
          AuthnContextClassContext authnContextClassContext = this.authnContextService.getAuthnContextClassContext(context);
          for (String loa : authnContextClassContext.getAuthnContextClassRefs()) {
            if (!this.isSignMessageURI(loa)) {
              log.info("SP has requested the SignMessage must be displayed, removing '{}' ... [{}]", loa, logId);
              authnContextClassContext.deleteAuthnContextClassRef(loa);
            }
          }
          if (authnContextClassContext.isEmpty()) {
            final String msg = "No valid sigmessage AuthnContext URI:s were specified in AuthnRequest";
            log.info("{} - can not proceed [{}]", msg, logId);
            throw new ExternalAutenticationErrorCodeException(AuthnEventIds.REQUEST_UNSUPPORTED, msg);
          }
        }

        // Finally, check that the DisplayEntity matches our IdP entityID.
        //
        if (signMessageContext.getSignMessage().getDisplayEntity() != null) {
          if (!this.entityID.equals(signMessageContext.getSignMessage().getDisplayEntity())) {
            final String msg = String.format("DisplayEntity (%s) of SignMessage does not match IdP entityID (%s)",
              signMessageContext.getSignMessage().getDisplayEntity(), this.entityID);
            log.info("{} - can not proceed [{}]", msg, logId);
            throw new ExternalAutenticationErrorCodeException(AuthnEventIds.REQUEST_UNSUPPORTED, msg);
          }
        }

        signMessageContext.setDisplayMessage(true);
      }
    }

    // Time to check SADRequest ...
    //
    SignatureActivationDataContext sadContext = this.getSadContext(context);
    if (sadContext != null) {

      if (isSignatureService) {
        // If a SADRequest is passed, a SignMessage must also be present.
        //
        if (signMessageContext == null) {
          final String msg = "Request contained SADRequest but no SignMessage was received - not allowed";
          log.info("{} - can not proceed [{}]", msg, logId);
          throw new ExternalAutenticationErrorCodeException(ExtAuthnEventIds.SWEID_BAD_REQUEST, msg);
        }
        else if (!signMessageContext.isDisplayMessage()) {
          // If we cannot display the SignMessage we can not issue a SAD ...
          final String msg = "SignMessage can not be displayed and SAD is requested";
          log.info("{} - can not proceed [{}]", msg, logId);
          throw new ExternalAutenticationErrorCodeException(ExtAuthnEventIds.SWEID_BAD_REQUEST, msg);
        }
        else {
          // Verify the SAD request ...
          //
          this.verifySadRequest(sadContext, context);
        }
      }
      else {
        log.warn("Requesting SP is not a signature service, but included SAPRequest extension in request, ignoring ... [{}]", logId);
        AuthenticationContext authnContext = this.getAuthenticationContext(context);
        authnContext.removeSubcontext(SignatureActivationDataContext.class);
      }
    }

  }

  /**
   * Verifies a received SAD request.
   * 
   * @param sadRequest
   *          the request to verify
   * @param context
   *          the context
   * @throws ExternalAutenticationErrorCodeException
   *           for errors
   */
  protected void verifySadRequest(SignatureActivationDataContext sadRequest, ProfileRequestContext<?, ?> context)
      throws ExternalAutenticationErrorCodeException {

    final AuthnRequest authnRequest = this.getAuthnRequest(context);
    if (authnRequest == null) {
      log.error("No AuthnRequest available [{}]", this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.INVALID_AUTHN_CTX, "Missing AuthnRequest");
    }

    final SADRequest r = sadRequest.getSadRequest();

    // Verify the version is what we understand ...
    //
    if (r.getRequestedVersion() != null && !supportedSadVersions.contains(r.getRequestedVersion())) {
      final String msg = String.format("Requested SAD version (%s) is not supported by the IdP", r.getRequestedVersion());
      log.info("{} [{}]", msg, this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(ExtAuthnEventIds.BAD_SAD_REQUEST, msg);
    }

    // Check the RequesterID ...
    //
    if (!StringUtils.hasText(r.getRequesterID())) {
      final String msg = "RequesterID is not present in the SADRequest - invalid";
      log.info("{} [{}]", msg, this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(ExtAuthnEventIds.BAD_SAD_REQUEST, msg);
    }
    final String issuer = authnRequest.getIssuer().getValue();
    if (!r.getRequesterID().equals(issuer)) {
      final String msg = String.format("Invalid RequestID of SADRequest (%s) - Issuer of AuthnRequest is '%s'", r.getRequesterID(), issuer);
      log.info("{} [{}]", msg, this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(ExtAuthnEventIds.BAD_SAD_REQUEST, msg);
    }

    // Verify that the SignRequestID is there ...
    //
    if (!StringUtils.hasText(r.getSignRequestID())) {
      final String msg = "SignRequestID is not present in the SADRequest - invalid";
      log.info("{} [{}]", msg, this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(ExtAuthnEventIds.BAD_SAD_REQUEST, msg);
    }

    // Assert that we have a DocCount element ...
    //
    if (r.getDocCount() == null) {
      final String msg = "DocCount is not present in the SADRequest - invalid";
      log.info("{} [{}]", msg, this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(ExtAuthnEventIds.BAD_SAD_REQUEST, msg);
    }

    // Assert that we have an ID for the SADRequest ...
    //
    if (!StringUtils.hasText(r.getID())) {
      final String msg = "ID attribute is not present in the SADRequest - invalid";
      log.info("{} [{}]", msg, this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(ExtAuthnEventIds.BAD_SAD_REQUEST, msg);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String issueSAD(ProfileRequestContext<?, ?> context, List<Attribute> attributes, String subjectAttributeName, String loa)
      throws ExternalAutenticationErrorCodeException {
    
    SignatureActivationDataContext sadContext = this.getSadContext(context);
    if (sadContext == null) {
      log.error("No SignatureActivationDataContext available [{}]", this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.INVALID_AUTHN_CTX, "Missing SignatureActivationDataContext");
    }
    
    Attribute subjectAttribute = attributes.stream()
        .filter(a -> a.getName().equals(subjectAttributeName))
        .findFirst()
        .orElse(null);
    if (subjectAttribute == null) {
      log.error("No {} attribute available", subjectAttributeName);
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.INVALID_AUTHN_CTX, "No principal attribute available");
    }

    final SADRequest sadRequest =  sadContext.getSadRequest();
    final SADVersion version = sadRequest.getRequestedVersion() != null ? sadRequest.getRequestedVersion() : SADVersion.VERSION_10; 
        
    SAD sad = this.sadFactory.getBuilder()
        .subject(AttributeUtils.getAttributeStringValue(subjectAttribute))
        .audience(sadRequest.getRequesterID())
        .version(version)
        .inResponseTo(sadRequest.getID())
        .loa(loa)
        .requestID(sadRequest.getSignRequestID())
        .numberOfDocuments(sadRequest.getDocCount())
        .buildSAD();    
    
    sad.getSeElnSadext().setAttributeName(subjectAttributeName);
    
    log.debug("Issuing SAD: {} []", sad, this.getLogString(context));
    
    // Sign the SAD and return it ...
    //
    try {
      return this.signatureSupportKeyService.createSADJwt(sad);
    }
    catch (SignatureException | IOException e) {
      log.error("Failed to sign SAD JWT", e);
      // TODO: Change error code
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.INVALID_AUTHN_CTX, "Failed to create JWT");
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean supportsMimeType(SignMessageMimeTypeEnum mimeType) {
    if (this.supportedMimeTypes == null) {
      return true;
    }
    return this.supportedMimeTypes.stream().filter(m -> m.equalsIgnoreCase(mimeType.getMimeType())).findFirst().isPresent();
  }

  /** {@inheritDoc} */
  @Override
  public boolean supportsScal2() {
    return this.scal2Supported;
  }

  /** {@inheritDoc} */
  @Override
  public SignMessageContext getSignMessageContext(ProfileRequestContext<?, ?> context) {
    return signMessageContextLookupStrategy.apply(context);
  }

  /** {@inheritDoc} */
  @Override
  public SignatureActivationDataContext getSadContext(ProfileRequestContext<?, ?> context) {
    return sadContextLookupStrategy.apply(context);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSignatureServicePeer(ProfileRequestContext<?, ?> context) {
    EntityDescriptor peerMetadata = this.getPeerMetadata(context);
    if (peerMetadata == null) {
      log.error("No metadata available for connecting SP");
      return false;
    }
    return EntityCategoryMetadataHelper.getEntityCategories(peerMetadata)
      .stream()
      .filter(c -> EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri().equals(c))
      .findFirst()
      .isPresent();
  }

  /**
   * Utility method that returns the {@code AuthenticationContext}.
   * 
   * @param context
   *          the profile context
   * @return the {@code AuthenticationContext}
   * @throws ExternalAutenticationErrorCodeException
   *           if the context is not available
   */
  protected AuthenticationContext getAuthenticationContext(ProfileRequestContext<?, ?> context)
      throws ExternalAutenticationErrorCodeException {
    AuthenticationContext authnContext = authenticationContextLookupStrategy.apply(context);
    if (authnContext == null) {
      log.error("No AuthenticationContext available [{}]", this.getLogString(context));
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.INVALID_AUTHN_CTX, "Missing AuthenticationContext");
    }
    return authnContext;
  }

  /**
   * Predicate that tells if the supplied URI is a URI indicating sign message display.
   * 
   * @param uri
   *          the URI to test
   * @return {@code true} if the supplied URI is for sign message, and {@code false} otherwise
   */
  protected boolean isSignMessageURI(String uri) {
    LoaEnum loa = LoaEnum.parse(uri);
    return (loa != null && loa.isSignatureMessageUri());
  }

  /**
   * Assigns the {@link AuthnContextService} bean.
   * 
   * @param authnContextService
   *          service
   */
  public void setAuthnContextService(AuthnContextService authnContextService) {
    this.authnContextService = authnContextService;
  }

  /**
   * Assigns the signature support key service.
   * 
   * @param signatureSupportKeyService
   *          the service
   */
  public void setSignatureSupportKeyService(SignatureSupportKeyService signatureSupportKeyService) {
    this.signatureSupportKeyService = signatureSupportKeyService;
  }

  /**
   * Assigns the supported MIME types for signature messages.
   * 
   * @param supportedMimeTypes
   *          a list of MIME types
   */
  public void setSupportedMimeTypes(List<String> supportedMimeTypes) {
    this.supportedMimeTypes = supportedMimeTypes;
  }

  /**
   * Assigns the flag that tells whether this IdP supports SAD generation.
   * 
   * @param scal2Supported
   *          {@code true} if SCAL2 is supported and {@code false} otherwise
   */
  public void setScal2Supported(boolean scal2Supported) {
    this.scal2Supported = scal2Supported;
  }

  /**
   * Assigns the SAD factory bean used to create SAD attributes.
   * 
   * @param sadFactory
   *          SAD factory
   */
  public void setSadFactory(SADFactory sadFactory) {
    this.sadFactory = sadFactory;
  }

  /**
   * Assigns the IdP entityID.
   * 
   * @param entityID
   *          the IdP entityID
   */
  public void setEntityID(String entityID) {
    this.entityID = entityID;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.hasText(this.entityID, "Property 'entityID' must be assigned");
    Assert.notNull(this.authnContextService, "Property 'authnContextService' must be assigned");
    Assert.notNull(this.signatureSupportKeyService, "Property 'signatureSupportKeyService' must be assigned");
    Assert.notNull(this.sadFactory, "Property 'sadFactory' must be assigned");
  }

}
