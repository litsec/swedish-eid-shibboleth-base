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
