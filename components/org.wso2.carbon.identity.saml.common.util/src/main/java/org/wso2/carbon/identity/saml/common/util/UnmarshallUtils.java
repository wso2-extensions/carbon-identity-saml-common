/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.saml.common.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.lang.StringUtils;
import org.apache.xerces.impl.Constants;
import org.apache.xerces.util.SecurityManager;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.wso2.carbon.identity.saml.common.util.exception.IdentityUnmarshallingException;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * TODO - Add description for the class
 */
public class UnmarshallUtils {

    private static final Log log = LogFactory.getLog(UnmarshallUtils.class);
    private static final int ENTITY_EXPANSION_LIMIT = 0;

    /**
     * Constructing the SAML or XACML Objects from a String.
     *
     * @param xmlString Decoded SAML or XACML String.
     * @return SAML or XACML Object.
     * @throws IdentityUnmarshallingException if an XMLObject is not constructable.
     */
    public static XMLObject unmarshall(String xmlString) throws IdentityUnmarshallingException {

        try {
            DocumentBuilderFactory documentBuilderFactory = getSecuredDocumentBuilderFactory();
            documentBuilderFactory.setIgnoringComments(true);
            Document document = getDocument(documentBuilderFactory, xmlString);
            if (isSignedWithComments(document)) {
                documentBuilderFactory.setIgnoringComments(false);
                document = getDocument(documentBuilderFactory, xmlString);
            }
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (ParserConfigurationException | UnmarshallingException | SAXException | IOException e) {
            String message = "Error in constructing XML Object from the encoded String";
            throw new IdentityUnmarshallingException(message, e);
        }
    }

    /**
     * Return whether SAML Assertion has the canonicalization method.
     * set to 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'.
     *
     * @param document Document which contains the SAML Assertion.
     * @return true if canonicalization method equals to 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'.
     */
    private static boolean isSignedWithComments(Document document) {

        XPath xPath = XPathFactory.newInstance().newXPath();
        try {
            String assertionId = (String) xPath.compile("//*[local-name()='Assertion']/@ID")
                    .evaluate(document, XPathConstants.STRING);

            if (StringUtils.isBlank(assertionId)) {
                return false;
            }

            NodeList nodeList = ((NodeList) xPath.compile(
                    "//*[local-name()='Assertion']" +
                            "/*[local-name()='Signature']" +
                            "/*[local-name()='SignedInfo']" +
                            "/*[local-name()='Reference'][@URI='#" + assertionId + "']" +
                            "/*[local-name()='Transforms']" +
                            "/*[local-name()='Transform']" +
                            "[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#WithComments']")
                    .evaluate(document, XPathConstants.NODESET));
            return nodeList != null && nodeList.getLength() > 0;
        } catch (XPathExpressionException e) {
            String message = "Failed to find the canonicalization algorithm of the assertion. Defaulting to: " +
                    "http://www.w3.org/2001/10/xml-exc-c14n#";
            log.warn(message);
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            return false;
        }
    }

    /**
     *
     * @param documentBuilderFactory contains parsers that produces DOM Objects.
     * @param samlString string containing the SAML Assertion.
     * @return
     * @throws IOException if there is a failure in input operation.
     * @throws SAXException if there is a failure in parsing.
     * @throws ParserConfigurationException if a satisfying DocumentBuilder cannot be created with the configuration requested.
     */
    private static Document getDocument(DocumentBuilderFactory documentBuilderFactory, String samlString)
            throws IOException, SAXException, ParserConfigurationException {

        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(samlString.getBytes());
        return docBuilder.parse(inputStream);
    }

    /**
     * Create DocumentBuilderFactory with the XXE and XEE prevention measurements.
     *
     * @return DocumentBuilderFactory instance.
     */
    public static DocumentBuilderFactory getSecuredDocumentBuilderFactory() {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        try {
            dbf.setFeature(Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE, false);
            dbf.setFeature(Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE, false);
            dbf.setFeature(Constants.XERCES_FEATURE_PREFIX + Constants.LOAD_EXTERNAL_DTD_FEATURE, false);
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        } catch (ParserConfigurationException e) {
            log.error("Failed to load XML Processor Feature " + Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE + " or " +
                    Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE + " or " + Constants.LOAD_EXTERNAL_DTD_FEATURE +
                    " or secure-processing.");
        }

        SecurityManager securityManager = new SecurityManager();
        securityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT);
        dbf.setAttribute(Constants.XERCES_PROPERTY_PREFIX + Constants.SECURITY_MANAGER_PROPERTY, securityManager);

        return dbf;

    }
}
