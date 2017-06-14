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
 * <resolver:DataConnector id="ScriptedAttributeConnector" xsi:type="ScriptedDataConnector" customObjectRef="bean-name">
 *   <dc:Script><![CDATA[
 *     connectorResults.addAll(custom.resolve(profileContext, resolutionContext, subjects));
 *     ]]></dc:Script>
 * </resolver:DataConnector>
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
   * @params subjects an array of the {@code Subject} objects associated with this authorization. Note that these will
   *         only be present if the attribute resolution has been associated with an Authentication
   * @return a list of {@link IdPAttribute} objects
   */
  List<IdPAttribute> resolve(ProfileRequestContext<?, ?> profileRequestContext,
      AttributeResolutionContext attributeResolutionContext, Subject[] subjects);

}
