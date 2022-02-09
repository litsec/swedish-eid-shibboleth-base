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

import java.security.cert.X509Certificate;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.profile.context.ProfileInterceptorContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import se.litsec.shibboleth.idp.authn.context.HolderOfKeyContext;
import se.litsec.shibboleth.idp.authn.utils.ClientCertificateGetter;

/**
 * Actions that reads the client TLS certificate and saves it (for HoK-support).
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@SuppressWarnings("rawtypes")
public class ReadClientCertificateAction extends AbstractHolderOfKeyAction {

  /** Class logger. */
  private final Logger log = LoggerFactory.getLogger(ReadClientCertificateAction.class);

  /** Should we try to read the client cert at this point or wait until the authenticator? */
  private boolean readEagerly = true;

  /** Bean that reads the client TLS certificate. */
  private ClientCertificateGetter clientCertificateGetter;

  /**
   * Constructor.
   */
  public ReadClientCertificateAction() {
  }

  /** {@inheritDoc} */
  @Override
  protected void doExecute(final ProfileRequestContext profileRequestContext, final ProfileInterceptorContext interceptorContext) {

    if (!this.isHokActive()) {
      return;
    }
    if (!this.readEagerly) {
      return;
    }

    final HolderOfKeyContext holderOfKeyContext = new HolderOfKeyContext();
    profileRequestContext.addSubcontext(holderOfKeyContext);

    final X509Certificate clientCertificate = this.clientCertificateGetter.getCertificate(this.getHttpServletRequest());
    holderOfKeyContext.setClientCertificateRead(true);
    
    if (clientCertificate != null) {
      log.debug("{} Read client TLS certificate: {}", clientCertificate.getSubjectX500Principal());
      holderOfKeyContext.setClientCertificate(clientCertificate);
    }
    else {
      log.debug("{} No client TLS certificate available", this.getLogPrefix());
    }
  }

  /**
   * Should we try to read the client cert at this point or wait until the authenticator?
   * 
   * @param readEagerly
   *          whether to read certificate in this action
   */
  public void setReadEagerly(final boolean readEagerly) {
    this.readEagerly = readEagerly;
  }

  /**
   * Assigns the bean that reads the client TLS certificate.
   * 
   * @param clientCertificateGetter
   *          getter bean
   */
  public void setClientCertificateGetter(final ClientCertificateGetter clientCertificateGetter) {
    this.clientCertificateGetter = clientCertificateGetter;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected void doInitialize() throws ComponentInitializationException {
    super.doInitialize();
    if (this.isHokActive()) {
      if (this.clientCertificateGetter == null) {
        throw new ComponentInitializationException("clientCertificateGetter must be set");
      }
    }
  }

}
