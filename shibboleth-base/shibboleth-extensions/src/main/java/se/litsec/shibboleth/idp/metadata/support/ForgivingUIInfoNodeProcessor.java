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
package se.litsec.shibboleth.idp.metadata.support;

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;

import org.opensaml.core.xml.LangBearing;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.saml2.metadata.Organization;

import net.shibboleth.idp.saml.metadata.impl.UIInfoNodeProcessor;

/**
 * The default {@link UIInfoNodeProcessor} fails if there is a {@code UIInfo} or {@code Organization} that has the
 * several elements with the same language. OK, it's a fault, but one sloppy SP shouldn't mess up the entire federation
 * for the IdP. The {@code ForgivingUIInfoNodeProcessor} class ensures that we don't run into this problem.
 * 
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 */
public class ForgivingUIInfoNodeProcessor extends UIInfoNodeProcessor {

  /** {@inheritDoc} */
  @Override
  public void process(final XMLObject metadataNode) throws FilterException {

    XMLObject cleanedMetadata = null;
    
    if (metadataNode instanceof UIInfo) {
      cleanedMetadata = this.cleanUIInfo((UIInfo) metadataNode);
    }
    else if (metadataNode instanceof Organization) {
      cleanedMetadata = this.cleanOrganization((Organization) metadataNode);
    }

    if (cleanedMetadata != null) {
      super.process(cleanedMetadata);
    }
    else {
      super.process(metadataNode);
    }
  }
  
  private UIInfo cleanUIInfo(final UIInfo info) {
    cleanList(info.getDisplayNames());
    cleanList(info.getDescriptions());
    cleanList(info.getInformationURLs());
    cleanList(info.getKeywords());
    cleanList(info.getPrivacyStatementURLs());
    return info;
  }
  
  private Organization cleanOrganization(final Organization org) {
    cleanList(org.getDisplayNames());
    cleanList(org.getOrganizationNames());
    cleanList(org.getURLs());
    return org;
  }
  
  private static void cleanList(final List<? extends LangBearing> list) {
    if (list == null || list.size() < 2) {
      return;
    }
    
    final List<String> langs = new ArrayList<>();
    List<LangBearing> forRemoval = null; 
    final ListIterator<? extends LangBearing> it = list.listIterator();
    while (it.hasNext()) {
      final LangBearing item = it.next();
      final String lang = item.getXMLLang(); 
      if (lang == null) {
        continue;
      }
      if (langs.contains(lang)) {
        // remove is an unsupported operation for the OpenSAML ListView, so we save the object
        // for later removal.
        if (forRemoval == null) {
          forRemoval = new ArrayList<>();
        }
        forRemoval.add(item);
      }
      else {
        langs.add(lang);
      }
    }
    if (forRemoval != null) {
      for (final LangBearing lb :forRemoval) {
        list.remove(lb);
      }
    }
  }
  
}
