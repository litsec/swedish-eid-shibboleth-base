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
package se.litsec.shibboleth.idp.attribute.resolver;

import java.security.Principal;

import net.shibboleth.idp.attribute.IdPAttribute;

/**
 * Interface that defines methods for converting a {@link Principal} object into a {@link IdPAttribute} object.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public interface PrincipalToIdpAttributeConverter {

  /**
   * Predicate that tells if this instance knows how to process the supplied principal.
   * <p>
   * Note that some implementations may look only at the supplied type, whereas others may perform more checks. It is
   * thus not certain that a later call to {@link #convert(Principal)} till return a {@code IdPAttribute} object, but
   * what is sure is that if the {@code supports} method returns {@code false} there is no point in invoking the
   * {@link #convert(Principal)} method.
   * </p>
   * 
   * @param principal
   *          the principal object to test
   * @return if this instance knows how to process the supplied principal {@code true} is returned, otherwise
   *         {@code false}
   */
  boolean supports(Principal principal);

  /**
   * Transforms the supplied principal object into an {@link IdPAttribute} object.
   * 
   * @param principal
   *          the principal to transform
   * @return an IdPAttribute or {@code null} if no attribute can be created
   */
  IdPAttribute convert(Principal principal);

}
