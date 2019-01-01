/**
 * Copyright 2017-2018 European Union
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

import java.util.List;
import java.util.Objects;

import de.interactive_instruments.SUtils;
import de.interactive_instruments.etf.dal.dto.capabilities.TestObjectDto;
import de.interactive_instruments.etf.dal.dto.capabilities.TestObjectTypeDto;
import de.interactive_instruments.etf.detector.DetectedTestObjectType;
import de.interactive_instruments.etf.model.EID;
import de.interactive_instruments.etf.model.EidHolder;
import de.interactive_instruments.etf.model.ExpressionType;
import de.interactive_instruments.etf.model.capabilities.Resource;
import de.interactive_instruments.etf.model.capabilities.TestObjectType;

/**
 * @author Jon Herrmann ( herrmann aT interactive-instruments doT de )
 */
class StdDetectedTestObjectType implements DetectedTestObjectType {

	private final TestObjectTypeDto testObjectType;
	private final String extractedLabel;
	private final String extractedDescription;
	private final Resource normalizedResource;
	private final int priority;

	StdDetectedTestObjectType(final TestObjectTypeDto testObjectType, final Resource normalizedResource) {
		this(testObjectType, normalizedResource, null, null, 0);
	}

	StdDetectedTestObjectType(final TestObjectTypeDto testObjectType,
			final Resource normalizedResource, final String label, final String description,
			final int priority) {
		this.testObjectType = Objects.requireNonNull(testObjectType);
		this.normalizedResource = Resource.toImmutable(Objects.requireNonNull(normalizedResource));
		this.extractedLabel = label;
		this.extractedDescription = description;
		this.priority = priority;
	}

	@Override
	public int hashCode() {
		return testObjectType.hashCode();
	}

	@Override
	public boolean equals(final Object obj) {
		return testObjectType.equals(obj);
	}

	@Override
	public List<TestObjectTypeDto> getSubTypes() {
		return testObjectType.getSubTypes();
	}

	@Override
	public List<String> getFilenameExtensions() {
		return testObjectType.getFilenameExtensions();
	}

	@Override
	public List<String> getMimeTypes() {
		return testObjectType.getMimeTypes();
	}

	@Override
	public String getDetectionExpression() {
		return testObjectType.getDetectionExpression();
	}

	@Override
	public ExpressionType getDetectionExpressionType() {
		return testObjectType.getDetectionExpressionType();
	}

	@Override
	public String getLabelExpression() {
		return testObjectType.getLabelExpression();
	}

	@Override
	public ExpressionType getLabelExpressionType() {
		return testObjectType.getLabelExpressionType();
	}

	@Override
	public String getDescriptionExpression() {
		return testObjectType.getDescriptionExpression();
	}

	@Override
	public ExpressionType getDescriptionExpressionType() {
		return testObjectType.getDescriptionExpressionType();
	}

	@Override
	public String getLabel() {
		return testObjectType.getLabel();
	}

	@Override
	public String getDescription() {
		return testObjectType.getDescription();
	}

	@Override
	public EID getId() {
		return testObjectType.getId();
	}

	@Override
	public TestObjectType getParent() {
		return testObjectType.getParent();
	}

	@Override
	public int compareTo(final Object o) {
		if (o instanceof StdDetectedTestObjectType) {
			return Integer.compare(priority, ((StdDetectedTestObjectType) (o)).priority);
		} else if (o instanceof EidHolder) {
			return getId().compareTo(((EidHolder) (o)).getId());
		}
		throw new IllegalArgumentException("Invalid object type comparison: " +
				o.getClass().getName() + " can not be compared.");
	}

	@Override
	public void enrichAndNormalize(final TestObjectDto testObject) {
		if (!SUtils.isNullOrEmpty(this.extractedLabel)) {
			testObject.setLabel(this.extractedLabel);
		}
		if (!SUtils.isNullOrEmpty(this.extractedDescription)) {
			testObject.setDescription(this.extractedDescription);
		}
		if (normalizedResource.getUri() != null && testObject.getResourceCollection() != null
				&& !testObject.getResourceCollection().isEmpty()) {
			testObject.getResourceCollection().iterator().next().setUri(
					normalizedResource.getUri());
		}
		testObject.setTestObjectType(this.testObjectType);
	}

	@Override
	public Resource getNormalizedResource() {
		return Resource.toImmutable(this.normalizedResource);
	}

	@Override
	public TestObjectTypeDto toTestObjectTypeDto() {
		return testObjectType.createCopy();
	}
}
