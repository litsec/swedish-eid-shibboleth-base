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
