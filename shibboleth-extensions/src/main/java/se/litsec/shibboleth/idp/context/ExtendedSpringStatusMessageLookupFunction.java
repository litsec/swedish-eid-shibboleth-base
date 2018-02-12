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
package se.litsec.shibboleth.idp.context;

import java.util.Locale;

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

  /** Locale to use for error messages. If not assigned, the locale from the request context is used. */
  protected Locale locale;

  /** {@inheritDoc} */
  @Override
  public String apply(final ProfileRequestContext input) {
    if (input != null && messageSource != null) {
      final SpringRequestContext springContext = input.getSubcontext(SpringRequestContext.class);
      if (springContext != null) {
        final RequestContext springRequestContext = springContext.getRequestContext();
        final Event previousEvent = springRequestContext != null ? springRequestContext.getCurrentEvent() : null;
        if (previousEvent != null) {
          try {
            String msg = messageSource.getMessage(previousEvent.getId(), null, this.getLocale(springRequestContext));
            return this.messageSource.getMessage(msg + ".message", null, msg, this.getLocale(springRequestContext));
          }
          catch (final NoSuchMessageException e) {
            return null;
          }
        }
      }
    }

    return null;
  }

  /**
   * Returns the locale to use when resolving messages.
   * 
   * @param context
   *          the request context
   * @return the locale to use
   */
  protected Locale getLocale(RequestContext context) {
    return this.locale != null ? this.locale : context.getExternalContext().getLocale();
  }

  /** {@inheritDoc} */
  @Override
  public void setMessageSource(final MessageSource source) {
    this.messageSource = source;
  }

  /**
   * Assigns the locale to use for error messages. If not assigned, the locale from the request context is used.
   * 
   * @param locale
   *          the locale to assign
   */
  public void setLocale(Locale locale) {
    this.locale = locale;
  }

}
