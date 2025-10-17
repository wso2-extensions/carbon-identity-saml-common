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
import org.opensaml.core.xml.XMLObject;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class UnmarshallUtilsTest {

    @BeforeMethod
    public void initialize() throws InitializationException {
        SAMLInitializer.doBootstrap();
    }

    @Test
    public void testUnmarshall() throws Exception {
        String xmlString = "<saml:Audience xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://sp.example.com/SAML2</saml:Audience>";
        XMLObject xmlObject = UnmarshallUtils.unmarshall(xmlString);
        assertEquals(xmlObject.getElementQName().getLocalPart(), "Audience", "Unmarshalled object doesn't match the " +
                "expected result");
    }
}
