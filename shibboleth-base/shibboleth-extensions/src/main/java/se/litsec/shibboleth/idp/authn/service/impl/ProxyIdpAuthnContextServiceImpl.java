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
package se.litsec.shibboleth.idp.authn.service.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.authn.AuthnEventIds;
import se.litsec.shibboleth.idp.authn.ExternalAutenticationErrorCodeException;
import se.litsec.shibboleth.idp.authn.context.AuthnContextClassContext;
import se.litsec.shibboleth.idp.authn.service.ProxyIdpAuthnContextService;

/**
 * Implementation of {@link ProxyIdpAuthnContextService}.
 *
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class ProxyIdpAuthnContextServiceImpl extends AuthnContextServiceImpl implements ProxyIdpAuthnContextService {

  /** Logging instance. */
  private final static Logger log = LoggerFactory.getLogger(ProxyIdpAuthnContextServiceImpl.class);

  /** {@inheritDoc} */
  @Override
  public List<String> getSendAuthnContextClassRefs(final ProfileRequestContext context, final List<String> assuranceURIs)
      throws ExternalAutenticationErrorCodeException {

    final String logId = this.getLogString(context);

    final AuthnContextClassContext authnContextClassContext = this.getAuthnContextClassContext(context);

    // Intermediate list holding the URI:s that should be sent in the AuthnRequest to the IdP.
    //
    List<String> urisToSend = new ArrayList<>();

    if (assuranceURIs == null || assuranceURIs.isEmpty()) {
      ProxyIdpAuthnContextServiceImpl.log.info(
        "No assurance certification specified by IdP - No matching against SP AuthnContext URI:s will be performed [{}]",
        logId);
      urisToSend.addAll(authnContextClassContext.getAuthnContextClassRefs());
    }
    else {
      for (final String uri : authnContextClassContext.getAuthnContextClassRefs()) {
        if (this.isSupported(context, uri, assuranceURIs)) {
          urisToSend.add(uri);
        }
        else {
          ProxyIdpAuthnContextServiceImpl.log.info("Requested AuthnContext URI '{}' is not supported by receiving IdP - will remove [{}]",
            uri, logId);
          authnContextClassContext.deleteAuthnContextClassRef(uri);
        }
      }
    }

    // There may be duplicates in the list.
    //
    urisToSend.stream().distinct().collect(Collectors.toList());

    // Transform list so that the IdP understands it.
    //
    urisToSend = this.transformForIdp(context, urisToSend);

    // Now, if no more AuthContext URI:s remain, we must fail since there is not point is sending a request
    // to the IdP and get back an Assertion that we can't return back to the SP.
    //
    if (urisToSend.isEmpty()) {
      final String msg = "No matching AuthnContext URI:s remain after matching against IdP declared assurance certification";
      ProxyIdpAuthnContextServiceImpl.log.info("{} - failing [{}]", msg, logId);
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.REQUEST_UNSUPPORTED, msg);
    }

    authnContextClassContext.setProxiedAuthnContextClassRefs(urisToSend);
    ProxyIdpAuthnContextServiceImpl.log.debug("Will include the following AuthnContextClassRef URI:s in AuthnContext: {} [{}]", urisToSend,
      logId);

    return authnContextClassContext.getProxiedAuthnContextClassRefs();
  }

  /**
   * A Proxy-IdP may communicate with an IdP that uses different URI declarations for the same type of authentication
   * methods, e.g., the Swedish eID framework and eIDAS has different URI:s for the same type of authentication. This
   * method will enable tranformation of URI:s and provide the possibility to match URI:s from different schemes.
   * <p>
   * The default implementation just checks if the supplied {@code uri} is part of the {@code assuranceURIs} list. To
   * implement different behaviour override this method.
   * </p>
   *
   * @param context
   *          the request context
   * @param uri
   *          the URI to test
   * @param assuranceURIs
   *          IdP assurance certification URI:s
   * @return true if there is a match, and false otherwise
   */
  protected boolean isSupported(final ProfileRequestContext context, final String uri, final List<String> assuranceURIs) {
    return assuranceURIs.contains(uri);
  }

  /**
   * A Proxy-IdP may communicate with an IdP that uses different URI declarations for the same type of authentication
   * methods, e.g., the Swedish eID framework and eIDAS has different URI:s for the same type of authentication.
   * Therefore, we may have to transform the URI:s that were calculated to be passed in the AuthnContext so that the
   * receiving IdP understands them.
   * <p>
   * The default implementation does no transformation and just returns the supplied {@code urisForRequest} list. To
   * implement different behaviour override this method.
   * </p>
   *
   * @param context
   *          the request context
   * @param urisForRequest
   *          the URI:s that were calculated to be passed in the AuthnContext to the IdP
   * @return a list of transformed URI:s
   */
  protected List<String> transformForIdp(final ProfileRequestContext context, final List<String> urisForRequest) {
    return urisForRequest;
  }

  /**
   * Since the SP and the remote IdP may work according to different AuthnContextClassRef definitions, we may have to
   * transform the URI received in the assertion from the IdP to something that the SP can understand when the Proxy-IdP
   * sends back its assertion. This method handles this transformation.
   * <p>
   * The default implementation does no transformation and simply returns the supplied {@code authnContextUri}. To
   * implement different behaviour override this method.
   * </p>
   *
   * @param context
   *          the request context
   * @param authnContextUri
   *          the URI received from the remote IdP
   * @return an URI that can be understood by the SP, or {@code null} if no mapping exists
   */
  protected String transformForSp(final ProfileRequestContext context, final String authnContextUri) {
    return authnContextUri;
  }

  /** {@inheritDoc} */
  @Override
  public String getReturnAuthnContextClassRef(final ProfileRequestContext context, final String authnContextUri) 
      throws ExternalAutenticationErrorCodeException {

    final String logId = this.getLogString(context);

    final AuthnContextClassContext authnContextClassContext = this.getAuthnContextClassContext(context);

    // Make sure we received one of the requested AuthnContextClassRef URI:s.
    //
    if (!this.isIssuedAuthnContextClassRefAccepted(context, authnContextUri)) {
      final String msg = String.format(
        "AuthnContextClassRef URI received in assertion from IdP (%s) does not match any of the URI:s sent in the AuthnRequest (%s)",
        authnContextUri, authnContextClassContext.getProxiedAuthnContextClassRefs());
      ProxyIdpAuthnContextServiceImpl.log.info("{} [{}]", msg, logId);
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.AUTHN_EXCEPTION, msg);
    }

    // OK, that seems OK. Next, we transform the URI.
    //
    final String authnContextUriForSp = this.transformForSp(context, authnContextUri);
    if (authnContextUriForSp == null) {
      // Should never happen since we matched everything before sending the request.
      final String msg = String.format("AuthnContextClassRef received from IdP '{}' cannot be transformed", authnContextUri);
      ProxyIdpAuthnContextServiceImpl.log.info("{} [{}]", msg, logId);
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.AUTHN_EXCEPTION, msg);
    }
    return authnContextUriForSp;
  }

  /**
   * Depending on the type of matching of AuthnContextClassRef URI:s that is used we check whether an issued URI is what
   * we can accept (corresponds to what we requested).
   * <p>
   * The default implementation used "exact" matching.
   * </p>
   *
   * @param context
   *          the request context
   * @param authnContextUri
   *          the URI received in the assertion from the remote IdP
   * @return if the URI is accepted {@code true} is returned, otherwise {@code false}
   */
  protected boolean isIssuedAuthnContextClassRefAccepted(final ProfileRequestContext context, final String authnContextUri) {

    try {
      final List<String> requested = this.getAuthnContextClassContext(context).getProxiedAuthnContextClassRefs();
      if (requested == null || requested.isEmpty()) {
        // If we did not request anything, we accept what we got.
        return true;
      }
      return requested.contains(authnContextUri);
    }
    catch (final ExternalAutenticationErrorCodeException e) {
      // Will fail later
      return false;
    }
  }

}
