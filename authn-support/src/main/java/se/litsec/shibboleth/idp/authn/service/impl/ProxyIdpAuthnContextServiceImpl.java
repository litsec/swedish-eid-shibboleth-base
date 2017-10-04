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
package se.litsec.shibboleth.idp.authn.service.impl;

import java.security.Principal;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import se.litsec.shibboleth.idp.authn.ExternalAutenticationErrorCodeException;
import se.litsec.shibboleth.idp.authn.context.AuthnContextClassContext;
import se.litsec.shibboleth.idp.authn.service.ProxyIdpAuthnContextService;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI.LoaEnum;

/**
 * Implementation of {@link ProxyIdpAuthnContextService}.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class ProxyIdpAuthnContextServiceImpl extends AuthnContextServiceImpl implements ProxyIdpAuthnContextService {

  /** Logging instance. */
  private final Logger log = LoggerFactory.getLogger(ProxyIdpAuthnContextServiceImpl.class);

  /** {@inheritDoc} */
  @Override
  public void matchIdpAssuranceURIs(ProfileRequestContext<?, ?> context, List<String> assuranceURIs, boolean idpSupportsSignMessage)
      throws ExternalAutenticationErrorCodeException {

    final String logId = this.getLogString(context);

    if (assuranceURIs == null || assuranceURIs.isEmpty()) {
      log.info("No assurance certification specified by IdP - No matching against SP AuthnContext URI:s will be performed [{}]", logId);
      return;
    }

    AuthnContextClassContext authnContextClassContext = this.getAuthnContextClassContext(context);
    if (authnContextClassContext == null) {
      log.error("No RequestedAuthnContextClassContext available [{}]", logId);
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.INVALID_AUTHN_CTX, "Missing AuthnContextClassContext");
    }

    for (String uri : authnContextClassContext.getBaseAuthnContextClassRefs()) {
      if (!assuranceURIs.contains(uri)) {
        log.info("Requested AuthnContext URI '{}' is not supported by receiving IdP - will remove [{}]", uri, logId);
        authnContextClassContext.deleteAuthnContextClassRef(uri);

        // If the receiving IdP does not support the sigmessage-URI:s (or SignMessage in general), we also make sure
        // to remove the sigmessage-URI corresponding to the URI that we just removed.
        //
        if (!idpSupportsSignMessage) {
          for (String sigUri : authnContextClassContext.getSigMessageAuthnContextClassRefs()) {
            LoaEnum loa = LoaEnum.minusSigMessage(LoaEnum.parse(sigUri));
            if (uri.equals(loa.getUri())) {
              log.info("Receiving IdP does not support sigmessage - Removing '{}' since '{}' was not supported by IdP [{}]", 
                sigUri, uri, logId);
              authnContextClassContext.deleteAuthnContextClassRef(sigUri);
            }
          }
        }
      }
    }
    if (idpSupportsSignMessage) {
      for (String sigUri : authnContextClassContext.getSigMessageAuthnContextClassRefs()) {
        if (!assuranceURIs.contains(sigUri)) {
          log.info("Requested AuthnContext URI '{}' is not supported by receiving IdP - will remove [{}]", sigUri, logId);
          authnContextClassContext.deleteAuthnContextClassRef(sigUri);
        }
      }
    }

    // Now, if no more AuthContext URI:s remain, we must fail since there is not point is sending a request
    // to the IdP and get back an Assertion that we can't return back to the SP.
    //
    if (authnContextClassContext.isEmpty()) {
      final String msg = "No matching AuthnContext URI:s remain after matching against IdP declared assurance certification";
      log.info("{} - failing [{}]", msg, logId);
      throw new ExternalAutenticationErrorCodeException(AuthnEventIds.REQUEST_UNSUPPORTED, msg);
    }    
  }
  
  /** {@inheritDoc} */
  @Override
  public boolean verifyIssuedAuthnContextURI(ProfileRequestContext<?, ?> context, String authnContextUri) { 
    AuthnContextClassContext authnContextClassContext = this.getAuthnContextClassContext(context);
    if (authnContextClassContext == null) {
      log.error("No RequestedAuthnContextClassContext available");    
      return false;
    }    
    return authnContextClassContext.getValidAuthnContextClassRefs().contains(authnContextUri);
  }  

  /**
   * Overrides the default implementation so that more than one default URI is returned. The order of the list returned
   * depends on the rank each method is given in the Shibboleth configuration. The most preferred method is placed first
   * in the list.
   */
  @Override
  public List<String> getDefaultAuthnContextClassRefs(ProfileRequestContext<?, ?> context) {
    return this.authnContextweightMap.entrySet()
      .stream()
      .sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
      .map(Map.Entry::getKey)
      .filter(AuthnContextClassRefPrincipal.class::isInstance)
      .map(Principal::getName)
      .collect(Collectors.toList());
  }

}
