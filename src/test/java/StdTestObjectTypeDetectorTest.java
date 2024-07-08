/*
 * Copyright 2010-2017 interactive instruments GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import de.interactive_instruments.Credentials;
import de.interactive_instruments.IFile;
import de.interactive_instruments.UriUtils;
import de.interactive_instruments.etf.dal.dto.capabilities.ResourceDto;
import de.interactive_instruments.etf.dal.dto.capabilities.TestObjectDto;
import de.interactive_instruments.etf.detector.DetectedTestObjectType;
import de.interactive_instruments.etf.detector.IncompatibleTestObjectTypeException;
import de.interactive_instruments.etf.detector.TestObjectTypeDetectorManager;
import de.interactive_instruments.etf.detector.TestObjectTypeNotDetected;
import de.interactive_instruments.etf.model.capabilities.LocalResource;
import de.interactive_instruments.etf.model.capabilities.Resource;
import de.interactive_instruments.exceptions.ObjectWithIdNotFoundException;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static org.junit.Assert.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class StdTestObjectTypeDetectorTest {

	@Test
	public void test11_Wfs20() throws URISyntaxException, IOException, TestObjectTypeNotDetected {
		final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
				Resource.create("test",
						new URI("https://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-postgresql/wfs"
								+ "?request=GetCapabilities&service=wfs")));
		assertNotNull(detectedType);
		assertEquals("9b6ef734-981e-4d60-aa81-d6730a1c6389", detectedType.getId().toString());
		assertEquals("db12feeb-0086-4006-bc74-28f4fdef0171", detectedType.getParent().getId().toString());

		final TestObjectDto testObject = new TestObjectDto();
		testObject.addResource(new ResourceDto("serviceEndpoint", "http://none"));
		detectedType.enrichAndNormalize(testObject);

		assertEquals("SimpleDemo WFS", testObject.getLabel());
		assertEquals("SimpleDemo WFS by XtraServer", testObject.getDescription());
		assertEquals("https://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-postgresql/wfs"
				+ "?ACCEPTVERSIONS=2.0.0&request=GetCapabilities&service=WFS&VERSION=2.0.0", testObject.getResourceByName("serviceEndpoint").toString());
	}

	@Test
	public void test11_Wfs20_secured() throws URISyntaxException, IOException, TestObjectTypeNotDetected {
		// Important: only the http endpoint is secured with a password
		final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
				Resource.create("test",
						new URI("http://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-secured/wfs"
								+ "?request=GetCapabilities&service=wfs"), new Credentials("etf", "etf")));
		assertNotNull(detectedType);
		assertEquals("9b6ef734-981e-4d60-aa81-d6730a1c6389", detectedType.getId().toString());
		assertEquals("db12feeb-0086-4006-bc74-28f4fdef0171", detectedType.getParent().getId().toString());

		final TestObjectDto testObject = new TestObjectDto();
		testObject.addResource(new ResourceDto("serviceEndpoint", "http://none"));
		detectedType.enrichAndNormalize(testObject);

		assertEquals("SimpleDemo WFS", testObject.getLabel());
		assertEquals("SimpleDemo WFS by XtraServer", testObject.getDescription());
		assertEquals("http://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-secured/wfs"
				+ "?ACCEPTVERSIONS=2.0.0&request=GetCapabilities&service=WFS&VERSION=2.0.0", testObject.getResourceByName("serviceEndpoint").toString());
	}

	@Test
	public void test12_Wfs11() throws URISyntaxException, IOException, TestObjectTypeNotDetected,
			ObjectWithIdNotFoundException, IncompatibleTestObjectTypeException {
		final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
				Resource.create("test",
						new URI("https://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-postgresql/wfs"
								+ "?request=GetCapabilities&service=wfs")),
				TestObjectTypeDetectorManager.getTypes("bc6384f3-2652-4c7b-bc45-20cec488ecd0").keySet());
		assertNotNull(detectedType);
		assertEquals("bc6384f3-2652-4c7b-bc45-20cec488ecd0", detectedType.getId().toString());
		assertEquals("db12feeb-0086-4006-bc74-28f4fdef0171", detectedType.getParent().getId().toString());

		final TestObjectDto testObject = new TestObjectDto();
		testObject.addResource(new ResourceDto("serviceEndpoint", "http://none"));
		detectedType.enrichAndNormalize(testObject);

		assertEquals("SimpleDemo WFS", testObject.getLabel());
		assertEquals("SimpleDemo WFS by XtraServer", testObject.getDescription());
		assertEquals("https://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-postgresql/wfs"
				+ "?request=GetCapabilities&service=WFS&VERSION=1.1.0", testObject.getResourceByName("serviceEndpoint").toString());
	}

	@Test
	public void test13_Wfs20SelectHighest() throws URISyntaxException, IOException, TestObjectTypeNotDetected,
			ObjectWithIdNotFoundException, IncompatibleTestObjectTypeException {
		final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
				Resource.create("test",
						new URI("https://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-postgresql/wfs"
								+ "?request=GetCapabilities&service=wfs")),
				TestObjectTypeDetectorManager.getTypes("db12feeb-0086-4006-bc74-28f4fdef0171").keySet());
		assertNotNull(detectedType);
		assertEquals("9b6ef734-981e-4d60-aa81-d6730a1c6389", detectedType.getId().toString());
		assertEquals("db12feeb-0086-4006-bc74-28f4fdef0171", detectedType.getParent().getId().toString());

		final TestObjectDto testObject = new TestObjectDto();
		testObject.addResource(new ResourceDto("serviceEndpoint", "http://none"));
		detectedType.enrichAndNormalize(testObject);

		assertEquals("SimpleDemo WFS", testObject.getLabel());
		assertEquals("SimpleDemo WFS by XtraServer", testObject.getDescription());
		assertEquals("https://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-postgresql/wfs"
				+ "?ACCEPTVERSIONS=2.0.0&request=GetCapabilities&service=WFS&VERSION=2.0.0", testObject.getResourceByName("serviceEndpoint").toString());
	}

	@Test
	public void test14_incompleteWfs20Url() throws URISyntaxException, IOException, TestObjectTypeNotDetected,
			ObjectWithIdNotFoundException, IncompatibleTestObjectTypeException {
		// request with version=2.0.0 parameter instead of acceptversions
		final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
				Resource.create("test",
						new URI("https://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-postgresql/wfs"
								+ "?request=GetCapabilities&service=wfs&version=2.0.0")));
		assertNotNull(detectedType);
		assertEquals("9b6ef734-981e-4d60-aa81-d6730a1c6389", detectedType.getId().toString());
		assertEquals("db12feeb-0086-4006-bc74-28f4fdef0171", detectedType.getParent().getId().toString());

		final TestObjectDto testObject = new TestObjectDto();
		testObject.addResource(new ResourceDto("serviceEndpoint", "http://none"));
		detectedType.enrichAndNormalize(testObject);

		assertEquals("SimpleDemo WFS", testObject.getLabel());
		assertEquals("SimpleDemo WFS by XtraServer", testObject.getDescription());
		assertEquals("https://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-postgresql/wfs"
				+ "?ACCEPTVERSIONS=2.0.0&request=GetCapabilities&service=WFS&version=2.0.0", testObject.getResourceByName("serviceEndpoint").toString());
	}

	@Test
	public void test15_incompatibleTypes() throws URISyntaxException, IOException, TestObjectTypeNotDetected,
			ObjectWithIdNotFoundException, IncompatibleTestObjectTypeException {
		// Expecting WMS 1.1.0 but provide WFS 2.0.0 URL
		try {
			final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
					Resource.create("test",
							new URI("https://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-postgresql/wfs"
									+ "?request=GetCapabilities&service=wfs&version=2.0.0")),
					// Expect WMS
					TestObjectTypeDetectorManager.getTypes("d1836a8d-9909-4899-a0bc-67f512f5f5ac").keySet());
		}catch (IncompatibleTestObjectTypeException e) {
			assertEquals("9b6ef734-981e-4d60-aa81-d6730a1c6389",
					e.getDetectedTestObjectType().getId().getId());
			return;
		}
		fail("Exception expected");
	}

	@Test
	public void test16_incompatibleTypes() throws URISyntaxException, IOException, TestObjectTypeNotDetected,
			ObjectWithIdNotFoundException, IncompatibleTestObjectTypeException {
		try {
			// Expecting WMS 1.3 but provide WFS 2.0.0 URL
			final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
					Resource.create("test",
							new URI("https://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-postgresql/wfs"
									+ "?request=GetCapabilities&service=wfs&version=2.0.0")),
					// Expect WMS 1.3
					TestObjectTypeDetectorManager.getTypes("9981e87e-d642-43b3-ad5f-e77469075e74").keySet());
		}catch (final IncompatibleTestObjectTypeException e) {
			assertEquals("9b6ef734-981e-4d60-aa81-d6730a1c6389",
					e.getDetectedTestObjectType().getId().getId());
			return;
		}
		fail("Exception expected");
	}

	@Test(expected = TestObjectTypeNotDetected.class)
	public void test17_unknown() throws URISyntaxException, IOException, TestObjectTypeNotDetected, ObjectWithIdNotFoundException, IncompatibleTestObjectTypeException {
		final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
				Resource.create("test",
						new URI("https://www.interactive-instruments.de")));
	}

	@Test
	public void test17_cache() throws URISyntaxException, IOException, TestObjectTypeNotDetected, ObjectWithIdNotFoundException, IncompatibleTestObjectTypeException {
		test11_Wfs20();
		test11_Wfs20();
		test12_Wfs11();
		test13_Wfs20SelectHighest();
		test13_Wfs20SelectHighest();
		boolean exceptionThrown=false;
		try {
			test17_unknown();
		}catch(TestObjectTypeNotDetected e) {
			exceptionThrown=true;
		}
		assertTrue(exceptionThrown);
		test12_Wfs11();
		test11_Wfs20();
		test22_Wfs20FeatureCollectionFile();
		test15_incompatibleTypes();
		test16_incompatibleTypes();
	}

	@Test
	public void test21_CityGml20File() throws URISyntaxException, IOException, TestObjectTypeNotDetected {
		final IFile tmpDir = IFile.createTempDir("etf_junit");
		final IFile file = UriUtils.download(new URI("https://3d.bk.tudelft.nl/download/3dfier/Delft.gml.zip"));
		file.unzipTo(tmpDir);
		final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
				new LocalResource("dir",tmpDir));
		assertNotNull(detectedType);
		assertEquals("3e3639b1-f6b7-4d62-9160-963cfb2ea300", detectedType.getId().toString());
	}

	@Test
	public void test22_Wfs20FeatureCollectionFile() throws URISyntaxException, IOException, TestObjectTypeNotDetected {
		final IFile tmpDir = IFile.createTempDir("etf_junit");
		final IFile file = UriUtils.download(new URI("https://www.dropbox.com/s/uewjg48vq4owwlb/ps-ro-50.zip?dl=1"));
		file.unzipTo(tmpDir);
		final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
				new LocalResource("dir",tmpDir));
		assertNotNull(detectedType);
		assertEquals("a8a1b437-0ebf-454c-8204-bcf0b8548d8c", detectedType.getId().toString());
	}

	@Test
	public void test23_Wfs20FeatureCollectionFileWithExpectedType() throws URISyntaxException, IOException, TestObjectTypeNotDetected,
			ObjectWithIdNotFoundException, IncompatibleTestObjectTypeException {
		final IFile tmpDir = IFile.createTempDir("etf_junit");
		final IFile file = UriUtils.download(new URI("https://www.dropbox.com/s/uewjg48vq4owwlb/ps-ro-50.zip?dl=1"));
		file.unzipTo(tmpDir);
		final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
				new LocalResource("dir", tmpDir),
				TestObjectTypeDetectorManager.getTypes("a8a1b437-0ebf-454c-8204-bcf0b8548d8c").keySet());
		assertNotNull(detectedType);
		assertEquals("a8a1b437-0ebf-454c-8204-bcf0b8548d8c", detectedType.getId().toString());
	}

	public void test24_incompatibleTypes() throws URISyntaxException, IOException, TestObjectTypeNotDetected,
			ObjectWithIdNotFoundException, IncompatibleTestObjectTypeException {
		try {
			// Expecting GML FEATURE COLLECTION but provide WFS 2.0.0 URL
			final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
					Resource.create("test",
							new URI("https://services.interactive-instruments.de/cite-xs-46/simpledemo/cgi-bin/cities-postgresql/wfs"
									+ "?request=GetCapabilities&service=wfs")),
					TestObjectTypeDetectorManager.getTypes("e1d4a306-7a78-4a3b-ae2d-cf5f0810853e").keySet());
		}catch (final IncompatibleTestObjectTypeException e) {
			assertEquals("9b6ef734-981e-4d60-aa81-d6730a1c6389",
					e.getDetectedTestObjectType().getId().getId());
			return;
		}
		fail("Exception expected");
	}
	
	@Test
	public void test25_wmtsNoParameter() throws URISyntaxException, IOException, TestObjectTypeNotDetected,
			ObjectWithIdNotFoundException, IncompatibleTestObjectTypeException {
		// Assert detected WMTS without parameters
		try {
			final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
					Resource.create("test",
							new URI("http://www.ign.es/wmts/pnoa-ma")),
					TestObjectTypeDetectorManager.getTypes("ae35f7cd-86d9-475a-aa3a-e0bfbda2bb5f").keySet());
			
			assertNotNull(detectedType);
			assertEquals("ae35f7cd-86d9-475a-aa3a-e0bfbda2bb5f", detectedType.getId().toString());
			assertEquals("380b969c-215e-46f8-a4e9-16f002f7d6c3", detectedType.getParent().getId().toString());
			
		}catch (IncompatibleTestObjectTypeException e) {
			fail("Not an WMTS URL provided");
		}
		
	}

	@Test
	public void test26_wmtsIncompatibleType() throws URISyntaxException, IOException, TestObjectTypeNotDetected,
			ObjectWithIdNotFoundException, IncompatibleTestObjectTypeException {
		// Expecting WMS 1.3.0 but provide WMTS 1.0 URL
		try {
			final DetectedTestObjectType detectedType = TestObjectTypeDetectorManager.detect(
					Resource.create("test",
							new URI("http://www.ign.es/wmts/pnoa-ma")),
					// Expect WMS 1.3.0
					TestObjectTypeDetectorManager.getTypes("9981e87e-d642-43b3-ad5f-e77469075e74").keySet());
			
		}catch (IncompatibleTestObjectTypeException e) {
			assertEquals("ae35f7cd-86d9-475a-aa3a-e0bfbda2bb5f",
					e.getDetectedTestObjectType().getId().getId());
			return;
		}
		fail("Exception expected");
	}

}
