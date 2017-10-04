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
import java.util.List;

import org.opensaml.messaging.context.BaseContext;

import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI.LoaEnum;

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

  /** Base AuthnContextClassRef URI:s, meaning that they do not include a 'sigmessage' use. */
  private List<String> baseAuthnContextClassRefs = new ArrayList<>();

  /** AuthnContextClassRef URI:s that specify 'sigmessage' use. */
  private List<String> sigMessageAuthnContextClassRefs = new ArrayList<>();

  /** URI:s that are not understood by this IdP. */
  private List<String> unsupportedAuthnContextClassRefs = new ArrayList<>();

  /**
   * Constructor.
   * 
   * @param authnContextClassRefs
   *          the AuthnContextClassRef URI:s received in the SP AuthnRequest
   */
  public AuthnContextClassContext(List<String> authnContextClassRefs) {
    if (authnContextClassRefs == null) {
      return;
    }

    for (String uri : authnContextClassRefs) {
      LoaEnum loa = LoaEnum.parse(uri);
      if (loa == null) {
        this.unsupportedAuthnContextClassRefs.add(uri);
      }
      else if (loa.isSignatureMessageUri()) {
        if (!this.sigMessageAuthnContextClassRefs.contains(uri)) {
          this.sigMessageAuthnContextClassRefs.add(uri);
        }
      }
      else {
        if (!this.baseAuthnContextClassRefs.contains(uri)) {
          this.baseAuthnContextClassRefs.add(uri);
        }
      }
    }
  }

  /**
   * Returns a list of all valid URI:s held by the context.
   * 
   * @return a list of all valid URI:s
   */
  public List<String> getValidAuthnContextClassRefs() {
    List<String> uris = new ArrayList<String>(this.baseAuthnContextClassRefs);
    uris.addAll(this.sigMessageAuthnContextClassRefs);
    return uris;
  }

  /**
   * Returns the base AuthnContextClassRef URI:s.
   * 
   * @return an immutable list of base AuthnContextClassRef URI:s
   */
  public List<String> getBaseAuthnContextClassRefs() {
    return new ArrayList<>(this.baseAuthnContextClassRefs);
  }

  /**
   * Returns the sigmessage AuthnContextClassRef URI:s.
   * 
   * @return a list of sigmessage AuthnContextClassRef URI:s
   */
  public List<String> getSigMessageAuthnContextClassRefs() {
    return new ArrayList<>(this.sigMessageAuthnContextClassRefs);
  }

  /**
   * Returns the URI:s that are not understood by this IdP.
   * 
   * @return unsupported AuthnContextClassRef URI:s
   */
  public List<String> getUnsupportedAuthnContextClassRefs() {
    return new ArrayList<>(this.unsupportedAuthnContextClassRefs);
  }

  /**
   * After processing, the IdP may come to the conclusion that a certain URI that was requested can not be used. In
   * those cases it should call this method to delete it.
   * 
   * @param uri
   *          the URI to delete
   */
  public void deleteAuthnContextClassRef(String uri) {
    LoaEnum loa = LoaEnum.parse(uri);
    if (loa != null) {
      if (loa.isSignatureMessageUri()) {
        this.sigMessageAuthnContextClassRefs.remove(uri);
      }
      else {
        this.baseAuthnContextClassRefs.remove(uri);
      }
    }
  }

  /**
   * Predicate that returns {@code true} if the context does not hold any valid URI:s.
   * 
   * @return if no URI:s are stored {@code true} is returned, otherwise {@code false}
   */
  public boolean isEmpty() {
    return this.baseAuthnContextClassRefs.isEmpty() && this.sigMessageAuthnContextClassRefs.isEmpty();
  }

  /**
   * Predicate that returns {@code true} if the context does not hold any URI:s at all (including non supported).
   * 
   * @return if no URI:s are stored {@code true} is returned, otherwise {@code false}
   */
  public boolean isAllEmpty() {
    return this.baseAuthnContextClassRefs.isEmpty() && this.sigMessageAuthnContextClassRefs.isEmpty()
        && this.unsupportedAuthnContextClassRefs.isEmpty();
  }

}
