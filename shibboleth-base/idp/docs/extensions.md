# Extensions to Shibboleth for the Swedish eID Framework

This documents covers the extensions that have been made to the standard packaging of Shibboleth IdP 3.X in order to support the [Swedish eID Framework](https://github.com/elegnamnden/technical-framework).

### Attribute Support

### Status codes and Error Handling

Support for the following status codes has been added to [conf/errors.xml](src/main/resources/conf/errors.xml):

* `http://id.elegnamnden.se/status/1.0/cancel` - To be used as a second level status code when an authentication operation is cancelled by the user. This type of "error" is signalled to the Shibboleth flow using the event-ID `CancelAuthn`.
* `http://id.elegnamnden.se/status/1.0/fraud` - If the Identity Provider detects an ongoing fraud during an authentication operation this status code may be used to indicate this. The error is signalled using the event-ID `Fraud`.
* `http://id.elegnamnden.se/status/1.0/possibleFraud` - If the Identity Provider detects behaviour during an authentication operation that could be a fraud, and the policy states that the operation should be aborted, this status code may be used to indicate this. The error is signalled using the event-ID `PossibleFraud`.

The above status code are defined by the Swedish eID Framework in section 6.4 of "Deployment profile for the Swedish eID Framework".

### Messages

The default messages.properties file of the Shibboleth distribution has been translated into Swedish. See the file [messages/messages-sv.properties](src/main/resources/messages/messages-sv.properties).

Some message values from the default message file has been changed. See the file [messages/messages.properties](src/main/resources/messages/messages.properties).

The following message properties have been added:

* 


