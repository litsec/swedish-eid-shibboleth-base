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
package se.litsec.shibboleth.idp.authn;

import net.shibboleth.idp.authn.AuthnEventIds;

/**
 * Shibboleth defines the class {@link AuthnEventIds} that holds constants for events used in Shibboleth's Spring Web
 * Flow definitions. This class extends these constants with the events defined in the Swedish eID Shibboleth base
 * package.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 * @see AuthnEventIds
 */
public class ExtAuthnEventIds {

  /**
   * ID of event returned if the end user cancels an authentication process.
   */
  public static final String CANCEL_AUTHN = "CancelAuthn";
  
  /**
   * ID of event returned if the authentication process is terminated due to a detected fraud attempt.
   */
  public static final String FRAUD = "Fraud";
  
  /**
   * ID of event returned if the authentication process is terminated due to a possible (or suspected) fraud attempt.
   */
  public static final String POSSIBLE_FRAUD = "PossibleFraud";

}
