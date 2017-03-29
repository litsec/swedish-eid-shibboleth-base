package se.litsec.shibboleth.idp.attribute.resolver;

import java.util.List;

import javax.security.auth.Subject;

import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;

/**
 * Interface for the bean that is installed as a scriped attribute resolver in conf/attribute-resolver.xml.
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
   * Resolves the principal objects found into a list of IdPAttribute objects.
   * 
   * @param profileRequestContext
   *          the request context
   * @param attributeResolutionContext
   *          the resolution context
   * @params subjects an array of the {@code Subject} objects associated with this authorization. Note that these will
   *         only be present if the attribute resolution has been associated with an Authentication
   * @return a list of IdPAttribute objects
   */
  List<IdPAttribute> resolve(ProfileRequestContext<?, ?> profileRequestContext,
      AttributeResolutionContext attributeResolutionContext, Subject[] subjects);

}
