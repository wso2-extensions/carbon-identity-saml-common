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

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.GlobalParserPoolInitializer;
import org.opensaml.saml.config.impl.SAMLConfigurationInitializer;
import org.opensaml.xmlsec.config.GlobalAlgorithmRegistryInitializer;
import org.opensaml.xmlsec.config.impl.ApacheXMLSecurityInitializer;
import org.opensaml.xmlsec.config.impl.GlobalSecurityConfigurationInitializer;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;

/**
 * Initializes the OpenSAML 3 library at a central location to ensure that it is
 * accessible from any component.
 */
public class SAMLInitializer {

    /**
     * Initializes the required initializers.
     *
     * @throws InitializationException if initialization is unsuccessful
     */
    public static void doBootstrap() throws InitializationException {

        Thread thread = Thread.currentThread();
        ClassLoader originalClassLoader = thread.getContextClassLoader();
        thread.setContextClassLoader(InitializationService.class.getClassLoader());

        try {

            InitializationService.initialize();

            SAMLConfigurationInitializer samlConfigurationInitializer = new SAMLConfigurationInitializer();
            samlConfigurationInitializer.init();

            org.opensaml.saml.config.impl.XMLObjectProviderInitializer samlXMLObjectProviderInitializer =
                    new org.opensaml.saml.config.impl.XMLObjectProviderInitializer();
            samlXMLObjectProviderInitializer.init();

            org.opensaml.core.xml.config.XMLObjectProviderInitializer coreXMLObjectProviderInitializer =
                    new org.opensaml.core.xml.config.XMLObjectProviderInitializer();
            coreXMLObjectProviderInitializer.init();

            GlobalParserPoolInitializer globalParserPoolInitializer = new GlobalParserPoolInitializer();
            globalParserPoolInitializer.init();

            JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
            javaCryptoValidationInitializer.init();

            org.opensaml.xmlsec.config.impl.XMLObjectProviderInitializer xmlsecXMLObjectProviderInitializer =
                    new org.opensaml.xmlsec.config.impl.XMLObjectProviderInitializer();
            xmlsecXMLObjectProviderInitializer.init();

            ApacheXMLSecurityInitializer apacheXMLSecurityInitializer = new ApacheXMLSecurityInitializer();
            apacheXMLSecurityInitializer.init();

            GlobalSecurityConfigurationInitializer globalSecurityConfigurationInitializer =
                    new GlobalSecurityConfigurationInitializer();
            globalSecurityConfigurationInitializer.init();

            GlobalAlgorithmRegistryInitializer globalAlgorithmRegistryInitializer =
                    new GlobalAlgorithmRegistryInitializer();
            globalAlgorithmRegistryInitializer.init();

            org.opensaml.soap.config.impl.XMLObjectProviderInitializer soapXMLObjectProviderInitializer =
                    new org.opensaml.soap.config.impl.XMLObjectProviderInitializer();
            soapXMLObjectProviderInitializer.init();

            org.opensaml.xacml.profile.saml.config.impl.XMLObjectProviderInitializer
                    xacmlProfileXMLObjectProviderInitializer =
                    new org.opensaml.xacml.profile.saml.config.impl.XMLObjectProviderInitializer();
            xacmlProfileXMLObjectProviderInitializer.init();

            org.opensaml.xacml.config.impl.XMLObjectProviderInitializer xacmlXMLObjectProviderInitializer =
                    new org.opensaml.xacml.config.impl.XMLObjectProviderInitializer();
            xacmlXMLObjectProviderInitializer.init();

        } finally {
            thread.setContextClassLoader(originalClassLoader);
        }
    }
}
