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

  /** The RelayState sent from the SP-part of the Proxy-IdP. */
  private String relayState;

  /** The assertion received from the proxied IdP. */
  private Assertion assertion;

  /** Additional state data. */
  private Map<String, Object> additionalDataMap = new HashMap<>();

  /**
   * Constructor.
   * 
   * @param authnRequest
   *          the AuthnRequest sent by the SP-part of the Proxy-IdP
   * @param relayState
   *          the relay state (may be {@code null})
   */
  public ProxyIdpAuthenticationContext(AuthnRequest authnRequest, String relayState) {
    this.authnRequest = authnRequest;
    this.relayState = relayState;
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
   * Returns the relay state.
   * 
   * @return the relay state
   */
  public String getRelayState() {
    return this.relayState;
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
