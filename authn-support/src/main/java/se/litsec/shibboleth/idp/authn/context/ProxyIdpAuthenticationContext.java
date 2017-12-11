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
package se.litsec.shibboleth.idp.authn.context;

import java.util.HashMap;
import java.util.Map;

import org.opensaml.messaging.context.BaseContext;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;

/**
 * When Shibboleth is running as a Proxy-IdP, we need to be able to store information about the SP AuthnRequest that was
 * sent for later response processing. This context will store the necessary data.
 * <p>
 * The context can also be used to store assertion received from the proxied IdP.
 * </p>
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 *
 */
public class ProxyIdpAuthenticationContext extends BaseContext {

  /** The AuthnRequest sent by the SP-part of the Proxy-IdP. */
  private AuthnRequest authnRequest;

  /** The assertion received from the proxied IdP. */
  private Assertion assertion;

  /** Additional state data. */
  private Map<String, Object> additionalDataMap = new HashMap<>();

  /**
   * Constructor.
   * 
   * @param authnRequest
   *          the AuthnRequest sent by the SP-part of the Proxy-IdP
   */
  public ProxyIdpAuthenticationContext(AuthnRequest authnRequest) {
    this.authnRequest = authnRequest;
  }

  /**
   * Returns the AuthnRequest sent by the SP-part of the Proxy-IdP.
   * 
   * @return the AuthnRequest
   */
  public AuthnRequest getAuthnRequest() {
    return this.authnRequest;
  }

  /**
   * Returns the assertion.
   * 
   * @return the assertion or {@code null} if it is not set
   */
  public Assertion getAssertion() {
    return this.assertion;
  }

  /**
   * Assigns the assertion recived from the proxied IdP.
   * 
   * @param assertion
   *          the assertion to add
   */
  public void setAssertion(Assertion assertion) {
    this.assertion = assertion;
  }

  /**
   * Adds additional state data.
   * 
   * @param key
   *          the data key
   * @param data
   *          the data object
   */
  public void addAdditionalData(String key, Object data) {
    this.additionalDataMap.put(key, data);
  }

  /**
   * Retrieves additional state data.
   * 
   * @param key
   *          the data key
   * @return the data object, or {@code null}
   */
  public Object getAdditionalData(String key) {
    return this.additionalDataMap.get(key);
  }

  /**
   * Returns the additional data map.
   * 
   * @return the additional data map
   */
  public Map<String, Object> getAdditionalDataMap() {
    return this.additionalDataMap;
  }

  /**
   * Assigns the additional data map
   * 
   * @param additionalDataMap
   *          the additional data map
   */
  public void setAdditionalDataMap(Map<String, Object> additionalDataMap) {
    this.additionalDataMap = additionalDataMap;
  }

}
