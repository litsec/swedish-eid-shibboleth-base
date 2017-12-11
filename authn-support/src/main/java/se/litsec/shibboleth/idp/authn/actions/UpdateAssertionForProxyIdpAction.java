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
package se.litsec.shibboleth.idp.authn.actions;

import javax.annotation.Nullable;

import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import se.litsec.shibboleth.idp.authn.context.ProxyIdpAuthenticationContext;
import se.litsec.shibboleth.idp.authn.context.strategy.ProxyIdpAuthenticationContextLookup;

/**
 * Shobboleth action bean that is called at the end of putting together an assertion. It will update the assertion with
 * data specific for an Proxy IdP.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@SuppressWarnings("rawtypes")
public class UpdateAssertionForProxyIdpAction extends AbstractAuthenticationAction {

  /** Class logger. */
  private final Logger log = LoggerFactory.getLogger(UpdateAssertionForProxyIdpAction.class);

  /** Strategy used to locate the {@link Assertion} to operate on. */
  private Function<ProfileRequestContext, Assertion> assertionLookupStrategy;

  /** Strategy used to locate the Proxy IdP context holding the proxy information. */
  private Function<AuthenticationContext, ProxyIdpAuthenticationContext> proxyIdpAuthenticationContextLookupStrategy;

  /**
   * Constructor.
   */
  public UpdateAssertionForProxyIdpAction() {
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected void doExecute(ProfileRequestContext profileRequestContext, AuthenticationContext authenticationContext) {

    final ProxyIdpAuthenticationContext proxyContext = this.proxyIdpAuthenticationContextLookupStrategy.apply(authenticationContext);
    if (proxyContext == null) {
      return;
    }
    if (proxyContext.getAssertion() == null) {
      log.info("No Assertion saved in ProxyIdpAuthenticationContext - cannot process");
      return;
    }

    final Assertion assertion = assertionLookupStrategy.apply(profileRequestContext);
    if (assertion == null) {
      log.error("Unable to obtain Assertion to modify");
      ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
      return;
    }

    this.setAuthenticatingAuthority(assertion, proxyContext.getAssertion());
  }

  /**
   * Assigns the AuthenticatingAuthority element holding the issuer of the proxied assertion.
   * 
   * @param assertion
   *          the assertion to update
   * @param proxiedAssertion
   *          the proxied assertion
   */
  protected void setAuthenticatingAuthority(Assertion assertion, Assertion proxiedAssertion) {
    if (proxiedAssertion.getIssuer() == null || proxiedAssertion.getIssuer().getValue() == null) {
      log.warn("No issuer element found in proxied assertion");
      return;
    }
    if (assertion.getAuthnStatements().isEmpty()) {
      log.warn("No AuthnStatement available is assertion to update - will not process");
      return;
    }
    AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);
    if (authnStatement.getAuthnContext() == null) {
      log.warn("No AuthnContext found in assertion to update - will not process");
    }

    final XMLObjectBuilderFactory bf = XMLObjectProviderRegistrySupport.getBuilderFactory();

    SAMLObjectBuilder<AuthenticatingAuthority> aaBuilder = (SAMLObjectBuilder<AuthenticatingAuthority>) bf
      .<AuthenticatingAuthority> getBuilderOrThrow(AuthenticatingAuthority.DEFAULT_ELEMENT_NAME);

    AuthenticatingAuthority aa = aaBuilder.buildObject();
    aa.setURI(proxiedAssertion.getIssuer().getValue());

    authnStatement.getAuthnContext().getAuthenticatingAuthorities().add(aa);
    log.info("Updated Assertion with AuthenticatingAuthority ({})", aa.getURI());
  }

  /**
   * Set the strategy used to locate the {@link Assertion} to operate on.
   * 
   * @param strategy
   *          strategy used to locate the {@link Assertion} to operate on
   */
  public void setAssertionLookupStrategy(final Function<ProfileRequestContext, Assertion> strategy) {
    ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
    this.assertionLookupStrategy = Constraint.isNotNull(strategy, "Assertion lookup strategy cannot be null");
  }

  /**
   * Set the strategy used to locate the {@link ProxyIdpAuthenticationContext}.
   * 
   * @param strategy
   *          strategy used to locate the {@link ProxyIdpAuthenticationContext}
   */
  public void setProxyIdpAuthenticationContextLookupStrategy(
      final Function<AuthenticationContext, ProxyIdpAuthenticationContext> strategy) {
    ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
    this.proxyIdpAuthenticationContextLookupStrategy = Constraint.isNotNull(strategy,
      "ProxyIdPAuthenticationContext lookup strategy cannot be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doInitialize() throws ComponentInitializationException {
    super.doInitialize();

    if (this.assertionLookupStrategy == null) {
      this.assertionLookupStrategy = new AssertionStrategy();
    }
    if (this.proxyIdpAuthenticationContextLookupStrategy == null) {
      this.proxyIdpAuthenticationContextLookupStrategy = new ProxyIdpAuthenticationContextLookup();
    }
  }

  private class AssertionStrategy implements Function<ProfileRequestContext, Assertion> {

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Assertion apply(@Nullable final ProfileRequestContext input) {
      if (input != null && input.getOutboundMessageContext() != null) {
        final Object outboundMessage = input.getOutboundMessageContext().getMessage();

        if (outboundMessage != null) {
          if (outboundMessage instanceof Assertion) {
            return (Assertion) outboundMessage;
          }
          else if (outboundMessage instanceof Response) {
            Response r = (Response) outboundMessage;
            if (!r.getAssertions().isEmpty()) {
              return r.getAssertions().get(0);
            }
          }
        }
      }
      return null;
    }
  }

}
