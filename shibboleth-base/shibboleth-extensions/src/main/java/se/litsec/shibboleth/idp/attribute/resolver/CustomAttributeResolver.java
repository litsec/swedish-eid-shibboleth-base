/*
 * Copyright 2017-2021 Litsec AB
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

import java.util.List;

import javax.security.auth.Subject;

import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;

/**
 * Interface for the bean that is installed as a scripted attribute resolver in conf/attribute-resolver.xml.
 * <p>
 * The bean implementing this interface is installed as a custom resolver in the conf/attribute-resolver.xml file as
 * follows:
 * </p>
 * 
 * <pre>
 * {@code 
 * <resolver:DataConnector id="ScriptedAttributeConnector" xsi:type="ScriptedDataConnector" customObjectRef="bean-name">
 *   <dc:Script><![CDATA[
 *     connectorResults.addAll(custom.resolve(profileContext, resolutionContext, subjects));
 *     ]]></dc:Script>
 * </resolver:DataConnector>}
 * </pre>
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public interface CustomAttributeResolver {

  /**
   * Resolves the principal objects found into a list of {@link IdPAttribute} objects.
   * 
   * @param profileRequestContext
   *          the request context
   * @param attributeResolutionContext
   *          the resolution context
   * @param subjects an array of the {@code Subject} objects associated with this authorization. Note that these will
   *         only be present if the attribute resolution has been associated with an Authentication
   * @return a list of {@link IdPAttribute} objects
   */
  List<IdPAttribute> resolve(final ProfileRequestContext profileRequestContext,
      final AttributeResolutionContext attributeResolutionContext, final Subject[] subjects);

}
