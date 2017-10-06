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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.opensaml.messaging.context.BaseContext;

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

  /** Used by Proxy-IdP:s to save whether the IdP that is used for authentication supports sign messages. */
  private boolean proxiedIdPSupportsSignMessage = false;

  /**
   * A Proxy-IdP needs to remember which URI:s that were sent to the remote IdP so that it can perform a validation of
   * the received assertion. This property holds this or these URI:s.
   */
  protected List<String> proxiedAuthnContextClassRefs;

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
    this.proxiedIdPSupportsSignMessage = context.proxiedIdPSupportsSignMessage;
  }

  /**
   * Returns the AuthnContextClassRef URI:s held by the context.
   * <p>
   * Note that the returned list in unmodifiable.
   * </p>
   * 
   * @return a list of AuthnContextClassRef URI:s
   */
  public List<String> getAuthnContextClassRefs() {
    return Collections.unmodifiableList(this.authnContextClassRefs);
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
   * Used by Proxy-IdP:s to save whether the IdP that is used for authentication supports sign messages.
   * 
   * @return {@code true} if the peer IdP supports sign messages and {@code false} otherwise
   */
  public boolean isProxiedIdPSupportsSignMessage() {
    return this.proxiedIdPSupportsSignMessage;
  }

  /**
   * Assigns whether the peer IdP supports sign messages.
   * 
   * @param proxiedIdPSupportsSignMessage
   *          flag
   */
  public void setProxiedIdPSupportsSignMessage(boolean proxiedIdPSupportsSignMessage) {
    this.proxiedIdPSupportsSignMessage = proxiedIdPSupportsSignMessage;
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

}
