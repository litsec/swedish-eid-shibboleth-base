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
package se.litsec.shibboleth.idp.authn.service;

import java.util.List;

import org.opensaml.profile.context.ProfileRequestContext;

import se.litsec.shibboleth.idp.authn.ExternalAutenticationErrorCodeException;

/**
 * Extends the {@link AuthnContextService} interface with methods useful for a Proxy IdP.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public interface ProxyIdpAuthnContextService extends AuthnContextService {

  /**
   * The method matches the supplied URI:s from the IdP:s assurance certification against the
   * {@link AuthnContextClassContext} for the current request, and updates this context, i.e., removes those not
   * supported by the IdP.
   * <p>
   * If no AuthnContext URI:s remains in the {@link AuthnContextClassContext} after matching, an error is thrown since
   * this means that the SP request and what the IdP supports does not match.
   * </p>
   * <p>
   * If the supplied IdP assurance certification list is empty, no matching is performed.
   * </p>
   * <p>
   * We are running as a Proxy-IdP supporting the Swedish eID Signature Service concept, but we don't know if the
   * receiving IdP supports the concept of signature message, and it will be up to us to display the sign message and
   * just perform an ordinary authentication at the remote IdP. In that case we can't filter out 'sigmessage' URI:s.
   * Therefore, the method must be told whether the receiving IdP supports sign message (and understands the
   * sigmessage-URI:s).
   * </p>
   * <p>
   * Finally, a list of URI:s to include in the AuthnRequest to be sent to the IdP is returned. These are also saved in
   * the current {@link AuthnContextClassContext}.
   * </p>
   * 
   * @param context
   *          the request context
   * @param assuranceURIs
   *          IdP assurance certification URI:s
   * @param idpSupportsSignMessage
   *          does not receiving IdP support the sign message-concept?
   * @throws ExternalAutenticationErrorCodeException
   *           if no AuthnContext URI:s matches
   */
  List<String> getSendAuthnContextClassRefs(ProfileRequestContext<?, ?> context, List<String> assuranceURIs, boolean idpSupportsSignMessage)
      throws ExternalAutenticationErrorCodeException;

  /**
   * When the Proxy-IdP receives an assertion it contains an {@code AuthnContextClassRef} holding the URI describing how
   * the IdP authenticated the user. This method verifies that this URI matches any of the URI:s the IdP-Proxy SP
   * included in the AuthnRequest, and throws an exception otherwise.
   * <p>
   * If the above is successful BUT the external IdP did not support sign messages, we may have to return another URI
   * depending on whether the Proxy-IdP display an sign message. So, after the check, this method calculates which LoA
   * URI to use in the resulting assertion.
   * </p>
   * 
   * @param context
   *          the request mapping
   * @param authnContextUri
   *          the URI from the {@code AuthnContextClassRef} element of the assertion
   * @param displayedSignMessage
   *          flag telling if the connector displayed a sign message
   * @return the LoA URI to include in the assertion back to the SP
   * @throws ExternalAutenticationErrorCodeException
   *           if the issued URI can not be used in the Proxy-IdP assertion
   */
  String getReturnAuthnContextClassRef(ProfileRequestContext<?, ?> context, String authnContextUri, boolean displayedSignMessage)
      throws ExternalAutenticationErrorCodeException;

}
