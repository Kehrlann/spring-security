/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.ui;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Daniel Garnier-Moiroux
 * @since 6.4
 */
class HtmlTemplatesTests {

	@Test
	void processTemplateWhenNoVariablesThenRendersTemplate() {
		var template = """
				<ul>
					<li>Lorem ipsum dolor sit amet</li>
					<li>consectetur adipiscing elit</li>
					<li>sed do eiusmod tempor incididunt ut labore</li>
					<li>et dolore magna aliqua</li>
				</ul>
				""";

		assertThat(HtmlTemplates.fromTemplate(template).render()).isEqualTo(template);
	}

	@Test
	void renderWhenVariablesThenRendersTemplate() {
		var template = """
				<ul>
					<li>{{one}}</li>
					<li>{{two}}</li>
				</ul>
				""";

		var renderedTemplate = HtmlTemplates.fromTemplate(template)
			.withValue("one", "Lorem ipsum dolor sit amet")
			.withValue("two", "consectetur adipiscing elit")
			.render();

		assertThat(renderedTemplate).isEqualTo("""
				<ul>
					<li>Lorem ipsum dolor sit amet</li>
					<li>consectetur adipiscing elit</li>
				</ul>
				""");
	}

	@Test
	void renderWhenVariablesThenEscapedAndRender() {
		var template = "<p>{{content}}</p>";

		var renderedTemplate = HtmlTemplates.fromTemplate(template)
			.withValue("content", "The <a> tag is very common in HTML.")
			.render();

		assertThat(renderedTemplate).isEqualTo("<p>The &lt;a&gt; tag is very common in HTML.</p>");
	}

	@Test
	void renderWhenRawHtmlVariablesThenRendersTemplate() {
		var template = """
				<p>
					The {{title}} is a placeholder text used in print.
				</p>
				""";

		var renderedTemplate = HtmlTemplates.fromTemplate(template)
			.withRawHtml("title", "<strong>Lorem Ipsum</strong>")
			.render();

		assertThat(renderedTemplate).isEqualTo("""
				<p>
					The <strong>Lorem Ipsum</strong> is a placeholder text used in print.
				</p>
				""");
	}

	@Test
	void renderWhenRawHtmlVariablesThenTrimsTrailingNewline() {
		var template = """
				<ul>
				{{content}}
				</ul>
				""";

		var renderedTemplate = HtmlTemplates.fromTemplate(template)
			.withRawHtml("content", "<li>Lorem ipsum dolor sit amet</li>".indent(2))
			.render();

		assertThat(renderedTemplate).isEqualTo("""
				<ul>
				  <li>Lorem ipsum dolor sit amet</li>
				</ul>
				""");
	}

	@Test
	void renderWhenEmptyVariablesThenRender() {
		var template = """
				<li>One: {{one}}</li>
				{{two}}
				""";

		var renderedTemplate = HtmlTemplates.fromTemplate(template)
			.withValue("one", "")
			.withRawHtml("two", "")
			.render();

		assertThat(renderedTemplate).isEqualTo("""
				<li>One: </li>

				""");
	}

	@Test
	void renderWhenMissingVariablesThenRemovesPlaceholders() {
		var template = """
				<li>One: {{one}}</li>
				<li>Two: {{two}}</li>
				{{three}}
				""";

		var renderedTemplate = HtmlTemplates.fromTemplate(template)
			.withValue("one", "Lorem ipsum dolor sit amet")
			.render();

		assertThat(renderedTemplate).isEqualTo("""
				<li>One: Lorem ipsum dolor sit amet</li>
				<li>Two: </li>

				""");
	}

}
