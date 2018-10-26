# Required configuration settings

The following variables need to be assigned for a Shibboleth installation that is built using the Shibboleth base packaging.

### SAML NameID

- `idp.persistentId.sourceAttribute.value` - Assign the id of the Shibboleth attribute that should be used as input when calculating persistent NameID:s, e.g., "personalIdentityNumber".
- `idp.persistentId.salt.value` - Assign a random string that is to be used a salt for the hashing operation of a persistent NameID (at least 24 characters).

