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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import net.shibboleth.idp.profile.context.ProfileInterceptorContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import se.litsec.shibboleth.idp.authn.ExtAuthnEventIds;
import se.litsec.shibboleth.idp.authn.context.ClientTlsCertificateContext;

/**
 * Actions that reads the client TLS certificate and saves it (for HoK-support).
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@SuppressWarnings("rawtypes")
public class ReadClientCertificateAction extends AbstractHolderOfKeyAction {
  
  /** Class logger. */
  private final Logger log = LoggerFactory.getLogger(ReadClientCertificateAction.class);  
  
  /** Default attribute name that contains the client certificate. */
  public static final String DEFAULT_ATTRIBUTE_NAME = "javax.servlet.request.X509Certificate";
  
  private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
  private static final String END_CERT = "-----END CERTIFICATE-----";

  /**
   * Should the certificate be read from a header? The alternative (and the default) is to read from a request
   * attribute.
   */
  private boolean readFromHeader = false;

  /** If {@code readFromHeader} is {@code true}, the action will read the client certificate from this header. */
  private String headerName;

  /**
   * If {@code readFromHeader} is {@code false}, the action will read the client certificate from this request
   * attribute.
   */
  private String attributeName;
  
  /** For decoding certificates. */
  private static final CertificateFactory factory;

  static {
    try {
      factory = CertificateFactory.getInstance("X.509");
    }
    catch (CertificateException e) {
      throw new RuntimeException(e);
    }
  }

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
    
    X509Certificate clientCertificate = null;
    if (this.readFromHeader) {
      final String pem = this.getHttpServletRequest().getHeader(this.headerName);
      if (!StringUtils.hasText(pem)) {
        clientCertificate = this.parseCertificate(pem);
      }
    }
    else {
      final X509Certificate[] certs = (X509Certificate[]) this.getHttpServletRequest().getAttribute(this.attributeName);
      if (certs != null && certs.length > 0) {
        clientCertificate = certs[0];
      }
    }
    
    if (clientCertificate == null) {
      log.info("{} No client TLS certificate available", this.getLogPrefix());
      ActionSupport.buildEvent(profileRequestContext, ExtAuthnEventIds.MISSING_CLIENT_TLS_CERTIFICATE);
    }
    else {
      log.debug("{} Read client TLS certificate: {}", clientCertificate.getSubjectX500Principal());
      profileRequestContext.addSubcontext(new ClientTlsCertificateContext(clientCertificate));
    }
  }
  
  /**
   * Parses the supplied text into a certificate.
   * @param pem the PEM encoded certificate
   * @return a X509Certificate
   */
  private X509Certificate parseCertificate(final String pem) {
    if (pem.startsWith(BEGIN_CERT)) {
      try (InputStream is = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8))) {
        return (X509Certificate) factory.generateCertificate(is);
      }
      catch (final CertificateException | IOException e) {
      }
    }
    // OK, try with brute force ...
    final String value = pem.replace(BEGIN_CERT, "").replace(END_CERT, "").replaceAll("\\s", "");
    try (final InputStream is = new ByteArrayInputStream(Base64.getDecoder().decode(value))) {
      return (X509Certificate) factory.generateCertificate(is);
    }
    catch (final CertificateException | IOException e) {
      log.info("Failed to decode certificate from request header");
      return null;
    }
  }
  
  /**
   * Should the certificate be read from a header? The alternative (and the default) is to read from a request
   * attribute.
   * 
   * @param readFromHeader
   *          true if the action should read certificate from header
   */
  public void setReadFromHeader(final boolean readFromHeader) {
    this.readFromHeader = readFromHeader;
  }

  /**
   * If {@code readFromHeader} is {@code true}, the action will read the client certificate from the header given.
   * 
   * @param headerName
   *          the header name
   */
  public void setHeaderName(final String headerName) {
    this.headerName = headerName;
  }

  /**
   * If {@code readFromHeader} is {@code false}, the action will read the client certificate from this request
   * attribute.
   * 
   * @param attributeName
   *          the request attribute name
   */
  public void setAttributeName(final String attributeName) {
    this.attributeName = attributeName;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected void doInitialize() throws ComponentInitializationException {
    super.doInitialize();
    if (this.isHokActive()) {
      if (this.readFromHeader) {
        if (!StringUtils.hasText(this.headerName)) {
          throw new ComponentInitializationException("headerName must be set");
        }
      }
      else {
        if (!StringUtils.hasText(this.attributeName)) {
          this.attributeName = DEFAULT_ATTRIBUTE_NAME;
          log.debug("Setting attributeName to {}", DEFAULT_ATTRIBUTE_NAME);
        }
      }
    }
  }

}
