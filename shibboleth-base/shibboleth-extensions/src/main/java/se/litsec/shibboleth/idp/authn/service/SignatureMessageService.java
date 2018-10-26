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

import org.opensaml.profile.context.ProfileRequestContext;

import se.litsec.shibboleth.idp.authn.context.SignMessageContext;
import se.litsec.swedisheid.opensaml.saml2.signservice.dss.SignMessageMimeTypeEnum;

/**
 * Service for handling requests from a "Signature Service".
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 * @deprecated As of version 1.2, {@link SignSupportService} should be used instead
 */
@Deprecated
public interface SignatureMessageService extends AuthenticationBaseService {

  /**
   * Returns the {@link SignMessageContext} for the current authentication.
   * 
   * @param context
   *          the profile context
   * @return the {@code SignMessageContext}, or {@code null} if none is found
   */
  SignMessageContext getSignMessageContext(ProfileRequestContext<?, ?> context);

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

}
