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
package se.litsec.shibboleth.idp.authn.service;

import java.util.List;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.Attribute;

import se.litsec.shibboleth.idp.authn.ExternalAutenticationErrorCodeException;
import se.litsec.shibboleth.idp.authn.context.SignMessageContext;
import se.litsec.shibboleth.idp.authn.context.SignatureActivationDataContext;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessageMimeTypeEnum;

/**
 * Service for handling requests from a "Signature Service".
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public interface SignSupportService extends AuthenticationBaseService {

  /**
   * Returns the {@link SignMessageContext} for the current authentication.
   * 
   * @param context
   *          the profile context
   * @return the {@code SignMessageContext}, or {@code null} if none is available
   */
  SignMessageContext getSignMessageContext(ProfileRequestContext<?, ?> context);

  /**
   * Returns the {@link SignatureActivationDataContext} for the current authentication.
   * 
   * @param context
   *          the profile context
   * @return the {@code SignatureActivationDataContext}, or {@code null} if none is available
   */
  SignatureActivationDataContext getSadContext(ProfileRequestContext<?, ?> context);

  /**
   * Utility method that finds out whether the request that we are processing was sent by a "signature service".
   * 
   * @param context
   *          the profile context
   * @return if the peer is a signature service {@code true} is returned, otherwise {@code false}
   */
  boolean isSignatureServicePeer(ProfileRequestContext<?, ?> context);

  /**
   * Predicate that tells whether the current IdP supports displaying a message of the supplied MIME type.
   * 
   * @param mimeType
   *          the type
   * @return {@code true} if the IdP can display messages of the supplied type, and {@code false} otherwise
   */
  boolean supportsMimeType(SignMessageMimeTypeEnum mimeType);

  /**
   * Predicate that tells whether the current IdP supports Sole Control Assurance Level 2 (SCAL2) and is able to
   * generate SAD-attributes.
   * 
   * @return {@code true} if the IdP is scal2 compliant and {@code false} otherwise
   */
  boolean supportsScal2();

  /**
   * Issues a SAD and creates a signed JWT.
   * 
   * @param context
   *          the profile context
   * @param attributes
   *          the attributes that are to be issued
   * @param subjectAttributeName
   *          the attribute name of the attribute holding the subject name
   * @param loa
   *          the level of assurance to be included in the assertion
   * @return a signed SAD JWT
   * @throws ExternalAutenticationErrorCodeException
   *           for errors
   */
  String issueSAD(ProfileRequestContext<?, ?> context, List<Attribute> attributes, String subjectAttributeName, String loa)
      throws ExternalAutenticationErrorCodeException;

}
