/*
 * Copyright 2017-2022 Litsec AB
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

import java.util.ArrayList;
import java.util.List;

import org.opensaml.messaging.context.BaseContext;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;

import net.shibboleth.idp.authn.context.RequestedPrincipalContext;

/**
 * Context class for holding the requested AuthnContextClassRef URI:s for a relying party. OpenSAML offers a similar
 * context, {@link RequestedPrincipalContext}, but this class contains very little logic. It merely holds a list of the
 * URI:s found in the request. The {@code RequestedAuthnContextClassContext} class contains only the
 * AuthnContextClassRef URI:s that can be used after filtering against the IdP:a declared assurance certifications, and
 * also filtering based on sign support.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class AuthnContextClassContext extends BaseContext {

  /** AuthnContextClassRef URI:s requested by the SP. May be filtered along the process. */
  protected List<String> authnContextClassRefs;

  /**
   * Holds information whether the a remote IdP supports the concept on non notified eID schemes, or if it treats
   * notified and non notified eID schemes the same. (Applies to proxy IdP:s and certain schemes).
   */
  private boolean supportsNonNotifiedConcept = false;

  /**
   * A Proxy-IdP needs to remember which URI:s that were sent to the remote IdP so that it can perform a validation of
   * the received assertion. This property holds this or these URI:s.
   */
  protected List<String> proxiedAuthnContextClassRefs;

  /**
   * The comparison for AuthnContext URI:s.
   */
  protected AuthnContextComparisonTypeEnumeration authnContextComparison = AuthnContextComparisonTypeEnumeration.EXACT;

  /**
   * Constructor.
   * 
   * @param authnContextClassRefs
   *          the AuthnContextClassRef URI:s received in the SP AuthnRequest
   */
  public AuthnContextClassContext(List<String> authnContextClassRefs) {
    this.authnContextClassRefs = authnContextClassRefs != null ? new ArrayList<>(authnContextClassRefs) : new ArrayList<>();
  }

  /**
   * Protected copy constructor (for subclasses).
   * 
   * @param context
   *          the context to copy
   */
  protected AuthnContextClassContext(AuthnContextClassContext context) {
    this.authnContextClassRefs = context.authnContextClassRefs;
    this.proxiedAuthnContextClassRefs = context.proxiedAuthnContextClassRefs;
  }

  /**
   * Returns the AuthnContextClassRef URI:s held by the context.
   * 
   * @return a list of AuthnContextClassRef URI:s
   */
  public List<String> getAuthnContextClassRefs() {
    return new ArrayList<>(this.authnContextClassRefs);
  }

  /**
   * After processing, the IdP may come to the conclusion that a certain URI that was requested can not be used. In
   * those cases it should call this method to delete it.
   * 
   * @param uri
   *          the URI to delete
   */
  public void deleteAuthnContextClassRef(String uri) {
    this.authnContextClassRefs.remove(uri);
  }

  /**
   * A Proxy-IdP needs to remember which URI:s that were sent to the remote IdP so that it can perform a validation of
   * the received assertion. This method returns these URI:s.
   * 
   * @return a list of {@code AuthnContextClassRef} URI:s
   */
  public List<String> getProxiedAuthnContextClassRefs() {
    return this.proxiedAuthnContextClassRefs;
  }

  /**
   * Returns the comparison method for AuthnContext URI comparisons.
   * 
   * @return a {@code AuthnContextComparisonTypeEnumeration} enum
   */
  public AuthnContextComparisonTypeEnumeration getAuthnContextComparison() {
    return this.authnContextComparison;
  }

  /**
   * Assigns the comparison method for AuthnContext URI comparisons.
   * 
   * @param authnContextComparison
   *          a {@code AuthnContextComparisonTypeEnumeration} enum
   */
  public void setAuthnContextComparison(AuthnContextComparisonTypeEnumeration authnContextComparison) {
    this.authnContextComparison = authnContextComparison;
  }

  /**
   * A Proxy-IdP needs to remember which URI:s that were sent to the remote IdP so that it can perform a validation of
   * the received assertion. This method assigns these URI:s.
   * 
   * @param proxiedAuthnContextClassRefs
   *          a list of {@code AuthnContextClassRef} URI:s
   */
  public void setProxiedAuthnContextClassRefs(List<String> proxiedAuthnContextClassRefs) {
    this.proxiedAuthnContextClassRefs = proxiedAuthnContextClassRefs;
  }

  /**
   * Predicate that returns {@code true} if the context does not hold any valid URI:s.
   * 
   * @return if no URI:s are stored {@code true} is returned, otherwise {@code false}
   */
  public boolean isEmpty() {
    return this.authnContextClassRefs.isEmpty();
  }

  /**
   * Tells whether the remote IdP supports a non notified eID scheme concept.
   * <p>
   * Default is {@code false}.
   * </p>
   * 
   * @return if the IdP supports the non notified concept {@code true} is returned, otherwise {@code false}
   */
  public boolean isSupportsNonNotifiedConcept() {
    return this.supportsNonNotifiedConcept;
  }

  /**
   * Assigns whether the remote IdP supports a non notified eID scheme concept.
   * 
   * @param supportsNonNotifiedConcept
   *          whether the IdP supports the non notified concept
   */
  public void setSupportsNonNotifiedConcept(boolean supportsNonNotifiedConcept) {
    this.supportsNonNotifiedConcept = supportsNonNotifiedConcept;
  }

}
