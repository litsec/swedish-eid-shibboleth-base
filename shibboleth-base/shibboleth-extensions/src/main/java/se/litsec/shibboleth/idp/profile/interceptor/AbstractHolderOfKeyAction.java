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
package se.litsec.shibboleth.idp.profile.interceptor;

import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.idp.profile.context.ProfileInterceptorContext;
import net.shibboleth.idp.profile.interceptor.AbstractProfileInterceptorAction;

/**
 * Abstract base class for actions for checking HoK.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@SuppressWarnings("rawtypes")
public class AbstractHolderOfKeyAction extends AbstractProfileInterceptorAction {
  
  /** Is the Holder-of-key profile active? */
  private boolean hokActive = false;
  
  /** {@inheritDoc} */
  @Override
  protected boolean doPreExecute(ProfileRequestContext profileRequestContext, ProfileInterceptorContext interceptorContext) {
    return this.hokActive;
  }

  /**
   * Assigns whether the Holder-of-key profile is active.
   * 
   * @param hokActive
   *          whether HoK is active
   */
  public void setHokActive(final boolean hokActive) {
    this.hokActive = hokActive;
  }

  /**
   * Tells whether HoK is active.
   * 
   * @return true if HoK is active and false otherwise
   */
  protected final boolean isHokActive() {
    return this.hokActive;
  }

}
