/**
 * Copyright 2017-2019 European Union
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * This work was supported by the EU Interoperability Solutions for
 * European Public Administrations Programme (http://ec.europa.eu/isa)
 * through Action 1.17: A Reusable INSPIRE Reference Platform (ARE3NA).
 */
package de.interactive_instruments.etf;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import javax.xml.xpath.XPathException;
import javax.xml.xpath.XPathExpressionException;

import jlibs.xml.DefaultNamespaceContext;
import jlibs.xml.sax.dog.XMLDog;
import jlibs.xml.sax.dog.XPathResults;

import org.jaxen.saxpath.SAXPathException;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;

import de.interactive_instruments.*;
import de.interactive_instruments.etf.dal.dto.capabilities.TestObjectTypeDto;
import de.interactive_instruments.etf.detector.DetectedTestObjectType;
import de.interactive_instruments.etf.detector.TestObjectTypeDetector;
import de.interactive_instruments.etf.model.DefaultEidMap;
import de.interactive_instruments.etf.model.EID;
import de.interactive_instruments.etf.model.EidMap;
import de.interactive_instruments.etf.model.capabilities.CachedRemoteResource;
import de.interactive_instruments.etf.model.capabilities.LocalResource;
import de.interactive_instruments.etf.model.capabilities.RemoteResource;
import de.interactive_instruments.etf.model.capabilities.Resource;
import de.interactive_instruments.exceptions.ExcUtils;
import de.interactive_instruments.exceptions.InitializationException;
import de.interactive_instruments.exceptions.InvalidStateTransitionException;
import de.interactive_instruments.exceptions.config.ConfigurationException;
import de.interactive_instruments.io.GmlAndXmlFilter;

/**
 * Standard detector for Test Object Types.
 *
 * The standard detector takes xpath expressions for detecting the test object types, and checks for matches in XML files. As the jdk xpath engine is very slow and memory hungry, the XMLDog engine which is based on Sax is used.
 *
 * Note: Only a subset of XPath 1.0 is supported https://github.com/santhosh-tekuri/jlibs/wiki/XMLDog
 *
 * @author Jon Herrmann ( herrmann aT interactive-instruments doT de )
 * @author Clemens Portele ( portele aT interactive-instruments doT de )
 */
public class StdTestObjectDetector implements TestObjectTypeDetector {

    private static Logger logger = LoggerFactory.getLogger(StdTestObjectDetector.class);
    private boolean initialized = false;

    private final List<CompiledDetectionExpression> detectionExpressions = new ArrayList<>();

    private final EidMap<CompiledDetectionExpression> detectionExpressionsEidMap = new DefaultEidMap<>();

    private final XMLDog xmlDog = new XMLDog(new DefaultNamespaceContext(), null, null);

    private static final String LINKS = "links";
    private static final String REL = "rel";
    private static final String CONFORMANCE = "conformance";
    private static final String HREF = "href";
    private static final String CONFORMS_TO = "conformsTo";
    private static final String CONFORMANCE_URL_COMPLIANT = "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core";

    @Override
    public EidMap<TestObjectTypeDto> supportedTypes() {
        return StdTestObjectTypes.types;
    }

    @Override
    public void init() throws ConfigurationException, InitializationException, InvalidStateTransitionException {
        for (final TestObjectTypeDto testObjectType : supportedTypes().values()) {
            if (!SUtils.isNullOrEmpty(testObjectType.getDetectionExpression())) {
                try {
                    final CompiledDetectionExpression compiledExpression = new CompiledDetectionExpression(testObjectType,
                            this.xmlDog);
                    detectionExpressions.add(compiledExpression);
                    detectionExpressionsEidMap.put(testObjectType.getId(), compiledExpression);
                } catch (final SAXPathException e) {
                    logger.error("Could not compile XPath expression: ", e);
                }
            }
        }
        Collections.sort(detectionExpressions);
        initialized = true;
    }

    @Override
    public boolean isInitialized() {
        return initialized;
    }

    @Override
    public void release() {
        detectionExpressions.clear();
        detectionExpressionsEidMap.clear();
        initialized = false;
    }

    private DetectedTestObjectType detectLocalFile(final XPathResults results,
            final LocalResource resource, final List<CompiledDetectionExpression> expressions) {
        for (final CompiledDetectionExpression detectionExpression : expressions) {
            try {
                final DetectedTestObjectType type = detectionExpression.getDetectedTestObjectType(
                        results, resource);
                if (type != null) {
                    return type;
                }
            } catch (ClassCastException | XPathExpressionException e) {
                logger.error("Could not evaluate XPath expression: ", e);
            }
        }
        return null;
    }

    /**
     * Detect Test Object Type from samples in a directory
     *
     * @param localResource
     *            directory as URI
     * @return Test Object Type or null if unknown
     * @throws IOException
     *             if an error occurs accessing the files
     */
    private DetectedTestObjectType detectInLocalDirFromSamples(final List<CompiledDetectionExpression> expressions,
            final LocalResource localResource) throws IOException {
        final IFile dir = localResource.getFile();
        final List<IFile> files = dir.getFilesInDirRecursive(GmlAndXmlFilter.instance().filename(), 6, false);
        if (files == null || files.size() == 0) {
            return null;
        }
        final TreeSet<DetectedTestObjectType> detectedTypes = new TreeSet<>();
        for (final IFile sample : Sample.normalDistributed(files, 7)) {
            try {
                final InputStream inputStream = new FileInputStream(sample);
                final DetectedTestObjectType detectedType = detectLocalFile(xmlDog.sniff(new InputSource(inputStream)),
                        localResource, expressions);
                if (detectedType != null) {
                    detectedTypes.add(detectedType);
                }
                if (detectedTypes.size() >= expressions.size()) {
                    // skip if we have detected types for all expressions
                    break;
                }
            } catch (XPathException e) {
                ExcUtils.suppress(e);
            }
        }
        if (detectedTypes.isEmpty()) {
            return null;
        }
        return detectedTypes.first();
    }

    /**
     *
     * @param detectionExpression
     * @param resource
     * @return
     */
    private DetectedTestObjectType detectRemote(final CompiledDetectionExpression detectionExpression,
            final CachedRemoteResource resource) {
        try {
            //
            final Resource normalizedResource = detectionExpression.getNormalizedResource(resource);

            if (detectionExpression.isApiFeatures("boolean(/child::*[local-name() = 'API_FEATURES'])") == false) {
                return detectionExpression.getDetectedTestObjectType(
                        xmlDog.sniff(new InputSource(normalizedResource.openStream())), normalizedResource);
            } else {
                // Get resource, collect URI and send request to check /conformance path
                if (checkResourcePath(normalizedResource.getUri())) {
                    final StdDetectedTestObjectType returned = new StdDetectedTestObjectType(
                            detectionExpression.getTestObjectType(),
                            normalizedResource);
                    return returned;
                }
            }
        } catch (IOException | XPathException | JSONException e) {
            logger.error("Error occurred during Test Object Type detection ", e);
        }
        return null;
    }

    private DetectedTestObjectType detectedType(final Resource resource,
            final List<CompiledDetectionExpression> expressions) {
        Collections.sort(expressions);

        // detect remote type
        if (resource instanceof RemoteResource) {
            final CachedRemoteResource cachedResource = Resource.toCached((RemoteResource) resource);
            for (final CompiledDetectionExpression expression : expressions) {
                final DetectedTestObjectType detectedType = detectRemote(expression, cachedResource);
                if (detectedType != null) {
                    return detectedType;
                }
            }
        } else {
            try {
                return detectInLocalDirFromSamples(expressions, (LocalResource) resource);
            } catch (IOException ign) {
                ExcUtils.suppress(ign);
                return null;
            }
        }
        return null;
    }

    @Override
    public DetectedTestObjectType detectType(final Resource resource, final Set<EID> expectedTypes) {

        // Types that can be detected by URI
        final List<CompiledDetectionExpression> uriDetectionCandidates = new ArrayList<>();
        // All others
        final List<CompiledDetectionExpression> expressionsForExpectedTypes = new ArrayList<>();
        for (final EID expectedType : expectedTypes) {
            final CompiledDetectionExpression detectionExpression = detectionExpressionsEidMap.get(expectedType);
            if (detectionExpression != null) {
                if (detectionExpression.isUriKnown(resource.getUri())) {
                    uriDetectionCandidates.add(detectionExpression);
                } else {
                    expressionsForExpectedTypes.add(detectionExpression);
                }
            }
        }
        if (!uriDetectionCandidates.isEmpty()) {
            // Test Object types could be detected by URI
            final DetectedTestObjectType detectedType = detectedType(resource, uriDetectionCandidates);
            if (detectedType != null) {
                return detectedType;
            }
        }
        // Test Object types could not be identified by URI
        final DetectedTestObjectType detectedType = detectedType(resource, expressionsForExpectedTypes);
        if (detectedType != null) {
            return detectedType;
        }

        // should never happen, fallback types are XML and WEBSERVICE
        return null;
    }

    @Override
    public DetectedTestObjectType detectType(final Resource resource) {
        return detectedType(resource, detectionExpressions);
    }

    private static boolean checkResourcePath(URI uri) throws IOException {
        try {
            String content = getContentFromUrl(uri.toURL());
            String conformanceHref = searchConformanceHref(new JSONObject(content));
            if (conformanceHref == null) {
                return false;
            }
            return checkConformanceHref(conformanceHref);
        } catch (IllegalArgumentException e) {
            logger.error("Error occurred during resource path checking process ", e);
            return false;
        }

    }

    private static String searchConformanceHref(JSONObject json) {
        if (json.has(LINKS)) {
            return StreamSupport.stream(json.getJSONArray(LINKS).spliterator(), false)
                    .map(JSONObject.class::cast)
                    .filter(o -> o.has(REL) && CONFORMANCE.equals(o.getString(REL)) && o.has(HREF))
                    .map(o -> o.getString(HREF))
                    .findFirst().orElse(null);
        }
        return null;
    }

    private static boolean checkConformanceHref(String href) throws IOException {
        String content = getContentFromUrl(new URL(href));
        JSONObject json = new JSONObject(content);
        if (json.has(CONFORMS_TO)) {
            return StreamSupport.stream(json.getJSONArray(CONFORMS_TO).spliterator(), false)
                    .map(String.class::cast)
                    .anyMatch(CONFORMANCE_URL_COMPLIANT::equals);
        }
        return false;
    }

    private static String getContentFromUrl(URL url) throws IOException {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
            return br.lines().collect(Collectors.joining(""));
        }
    }
}
