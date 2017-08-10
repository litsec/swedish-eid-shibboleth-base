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
package se.litsec.shibboleth.idp.context;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.profile.impl.AddStatusToResponse;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.NoSuchMessageException;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import com.google.common.base.Function;

import net.shibboleth.idp.profile.context.SpringRequestContext;
import net.shibboleth.idp.profile.context.navigate.SpringStatusMessageLookupFunction;

/**
 * The {@link SpringStatusMessageLookupFunction} is used by the Shibboleth "AddStatusToResponse" bean (see the
 * {@link AddStatusToResponse} class). It looks for a textual representation of an error code from Shibboleth's message
 * store (message.properties) and adds it to the {@code StatusMessage} element of the {@code Status}. However, error
 * codes in a Shibboleth message file is represented like the example below.
 * 
 * <pre>
 * AuthenticationException = authn
 * ...
 * authn.title = Login Failed
 * authn.message = User login was not successful or could not meet the requirements of the requesting application.
 * </pre>
 * 
 * This means that if the error code processed by the function is "AuthenticationException" the resulting error message
 * will be "authn", but we would rather have the message as pointed out by "authn.message".
 * 
 * <p>
 * The {@code ExtendedSpringStatusMessageLookupFunction} will compensate for this and revert to the default
 * implementation if there is no mapping for "x.message" where x is the error code.
 * </p>
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 * @see SpringStatusMessageLookupFunction
 */
@SuppressWarnings("rawtypes")
public class ExtendedSpringStatusMessageLookupFunction implements Function<ProfileRequestContext, String>, MessageSourceAware {

  /** The message source. */
  protected MessageSource messageSource;

  /** {@inheritDoc} */
  @Override
  public String apply(final ProfileRequestContext input) {
    if (input != null && messageSource != null) {
      final SpringRequestContext springContext = input.getSubcontext(SpringRequestContext.class);
      if (springContext != null) {
        final RequestContext springRequestContext = springContext.getRequestContext();
        final Event previousEvent = springRequestContext != null ? springRequestContext.getCurrentEvent() : null;
        if (previousEvent != null) {
          String eventId = previousEvent.getId();          
          try {
            String msg = messageSource.getMessage(previousEvent.getId(), null, springRequestContext.getExternalContext().getLocale());            
            return this.messageSource.getMessage(msg + ".message", null, msg, springRequestContext.getExternalContext().getLocale());
          }
          catch (final NoSuchMessageException e) {
            return null;
          }
        }
      }
    }

    return null;
  }

  /** {@inheritDoc} */
  @Override
  public void setMessageSource(final MessageSource source) {
    this.messageSource = source;
  }

}
