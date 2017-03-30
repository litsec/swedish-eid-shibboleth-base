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
package se.litsec.shibboleth.idp.authn.principal;

import javax.annotation.Nonnull;

import com.google.common.base.MoreObjects;

import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * A specialization of the {@link UsernamePrincipal} that represents the "personalIdentityNumber" attribute.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class PersonalIdentityNumberPrincipal extends UsernamePrincipal {

  /**
   * Constructor that initializes the instance with a personal identity number.
   * 
   * @param personalIdentityNumber
   *          the personal identity number
   */
  public PersonalIdentityNumberPrincipal(@Nonnull @NotEmpty @ParameterName(name = "personalIdentityNumber") String personalIdentityNumber) {
    super(personalIdentityNumber);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this).add("personalIdentityNumber", this.getName()).toString();
  }

}
