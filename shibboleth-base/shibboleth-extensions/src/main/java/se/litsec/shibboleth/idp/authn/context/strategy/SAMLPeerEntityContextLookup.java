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
package se.litsec.shibboleth.idp.authn.context.strategy;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;

/**
 * Lookup function for finding a {@link SAMLPeerEntityContext}.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
@SuppressWarnings("rawtypes")
public class SAMLPeerEntityContextLookup implements ContextDataLookupFunction<MessageContext, SAMLPeerEntityContext> {

  /** {@inheritDoc} */
  @Override
  public SAMLPeerEntityContext apply(MessageContext input) {
    return input != null ? input.getSubcontext(SAMLPeerEntityContext.class, false) : null;
  }

}
