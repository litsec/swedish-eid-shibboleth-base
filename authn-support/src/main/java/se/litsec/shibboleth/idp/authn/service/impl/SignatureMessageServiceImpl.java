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

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import se.litsec.shibboleth.idp.authn.ExtAuthnEventIds;
import se.litsec.shibboleth.idp.authn.ExternalAutenticationErrorCodeException;
import se.litsec.shibboleth.idp.authn.context.AuthnContextClassContext;
import se.litsec.shibboleth.idp.authn.context.SignMessageContext;
import se.litsec.shibboleth.idp.authn.context.strategy.SignMessageContextLookup;
import se.litsec.shibboleth.idp.authn.service.AuthnContextService;
import se.litsec.shibboleth.idp.authn.service.SignSupportService;
import se.litsec.shibboleth.idp.authn.service.SignatureMessageService;
import se.litsec.shibboleth.idp.subsystem.signservice.SignatureSupportKeyService;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI.LoaEnum;
import se.litsec.swedisheid.opensaml.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.litsec.swedisheid.opensaml.saml2.metadata.entitycategory.EntityCategoryMetadataHelper;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.Message;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessage;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessageMimeTypeEnum;

/**
 * Implementation of the {@link SignatureMessageService} interface.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 * @deprecated As of version 1.2, {@link SignSupportService} should be used instead
 */
@Deprecated
public class SignatureMessageServiceImpl extends AbstractAuthenticationBaseService implements SignatureMessageService, InitializingBean {

  /** Logging instance. */
  private final Logger log = LoggerFactory.getLogger(SignatureMessageServiceImpl.class);

  /** Strategy used to locate the SignMessageContext. */
  @SuppressWarnings("rawtypes")
  protected static Function<ProfileRequestContext, SignMessageContext> signMessageContextLookupStrategy = Functions
    .compose(new SignMessageContextLookup(), authenticationContextLookupStrategy);

  /** The AuthnContext service that helps us checking whether a request is valid. */
  protected AuthnContextService authnContextService;

  /** The SignatureSupportKey service. */
  protected SignatureSupportKeyService signatureSupportKeyService;

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
        AuthenticationContext authnContext = authenticationContextLookupStrategy.apply(context);
        if (authnContext == null) {
          log.error("No AuthenticationContext available [{}]", this.getLogString(context));
          throw new ExternalAutenticationErrorCodeException(AuthnEventIds.INVALID_AUTHN_CTX, "Missing AuthenticationContext");
        }
        authnContext.addSubcontext(new SignMessageContext(signMessage), true);
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
        AuthenticationContext authnContext = authenticationContextLookupStrategy.apply(context);
        if (authnContext == null) {
          log.error("No AuthenticationContext available [{}]", this.getLogString(context));
          throw new ExternalAutenticationErrorCodeException(AuthnEventIds.INVALID_AUTHN_CTX, "Missing AuthenticationContext");
        }
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

        signMessageContext.setDisplayMessage(true);
      }
    }

  }

  /** {@inheritDoc} */
  @Override
  public SignMessageContext getSignMessageContext(ProfileRequestContext<?, ?> context) {
    return signMessageContextLookupStrategy.apply(context);
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
   * The default implementation always returns {@code true}.
   */
  @Override
  public boolean supportsMimeType(SignMessageMimeTypeEnum mimeType) {
    return true;
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

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.authnContextService, "Property 'authnContextService' must be assigned");
    Assert.notNull(this.signatureSupportKeyService, "The property 'signatureSupportKeyService' must be assigned");
  }

}
