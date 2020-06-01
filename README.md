![Logo](https://github.com/litsec/eidas-opensaml/blob/master/docs/img/litsec-small.png)

------

# swedish-eid-shibboleth-base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.litsec.sweid.idp/shibboleth-base/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.litsec.sweid.idp/shibboleth-base)

Packaging of Shibboleth IdP 3.4.X prepared for the Swedish eID Framework

The swedish-eid-shibboleth-base repository is a re-packaging of the [Shibboleth Identity Provider](https://wiki.shibboleth.net/confluence/display/IDP30/Home) to enable a quick setup for an Identity Provider wanting to be compliant with the [Swedish eID Framework](https://github.com/swedenconnect/technical-framework).

The repository consists of the following components:

* dependency-bom - BOM (Bill of Materials) of dependencies for users of the base packaging of Shibboleth IdP 3.4.X for the Swedish eID Framework.

* shibboleth-base/shibboleth-extensions - Implementations that extend the core Shibboleth functionality with:
	* Contexts and extended sub-system support.
	
	* Extensions to Shibboleth's attribute support with converters and resolvers. The `SAML2AttributeNameToIdMapperService` is a service bean that maps between an SAML v2 attribute name and its corresponding Shibboleth attribute ID. This is useful for external authentication implementations that only knows about the actual SAML attribute name and not its Shibboleth ID.

	* Shibboleth's support for publishing IdP metadata is limited to a static JSP-file. Therefore a `MetadataPublishingController` class that supports publishing of signed, and up-to-date, metadata is added.

	* A framework for building and deploying an "external authentication" component in Shibboleth. The component comprises of the `AbstractExternalAuthenticationController` MVC-controller which is sub-classed to implement your own authentication, service implementations conforming to the Swedish eID Framework (signature services support, authentication context handling, ...) and other required extensions to support the Swedish eID Framework.


* shibboleth-base/idp - The actual re-packaging of the Shibboleth Identity Provider. It contains:
	- Definitions for all attributes defined in the Swedish eID Framework.
	- Attribute release rules for the Swedish eID Framework.
	- Extensions of the core SAML error codes with error codes defined within the Swedish eID Framework.
	- Metadata publishing support (via the `MetadataPublishingController` and metadata template support).
	- MVC setup for external authentication that enables us to implement an external authentication component in a Spring MVC controller instead of in a "raw" servlet.
	- The Shibboleth messages files in Swedish.
	- Some extensions to the core Shibboleth beans and flows.
	
### Upgrade notice

When upgrading to version 1.7.0 of the swedish-eid-shibboleth-base you should be aware that the version of the underlying Shibboleth version has been upgraded to v 3.4.4.

See the [Shibboleth 3.4 Release notes](https://wiki.shibboleth.net/confluence/display/IDP30/ReleaseNotes) for details.

Also note that if you have modifications to `services.xml` in the `conf` directory, you need to make sure that the `%{idp.home}/conf/custom-security-configuration.xml` is added to the `shibboleth.RelyingPartyResolverResources` bean.

```
<util:list id="shibboleth.RelyingPartyResolverResources">
  <value>%{idp.home}/conf/custom-security-configuration.xml</value>
  <value>%{idp.home}/conf/relying-party.xml</value>
  <value>%{idp.home}/conf/credentials.xml</value>
  <value>%{idp.home}/system/conf/relying-party-system.xml</value>
</util:list>
```

------

Copyright &copy; 2017-2020, [Litsec AB](http://www.litsec.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
