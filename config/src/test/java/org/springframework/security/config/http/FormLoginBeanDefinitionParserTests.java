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

package org.springframework.security.config.http;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.WebAttributes;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Luke Taylor
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class FormLoginBeanDefinitionParserTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/FormLoginBeanDefinitionParserTests";

	public static final String EXPECTED_HTML_HEAD = """
			  <head>
			    <meta charset="utf-8">
			    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
			    <meta name="description" content="">
			    <meta name="author" content="">
			    <title>Please sign in</title>
			    <style>
			    /* General layout */
			    body {
			      font-family: system-ui, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
			      background-color: #eee;
			      padding: 40px 0;
			      margin: 0;
			      line-height: 1.5;
			    }
			   \s
			    h2 {
			      margin-top: 0;
			      margin-bottom: 0.5rem;
			      font-size: 2rem;
			      font-weight: 500;
			      line-height: 2rem;
			    }
			   \s
			    .content {
			      margin-right: auto;
			      margin-left: auto;
			      padding-right: 15px;
			      padding-left: 15px;
			      width: 100%;
			      box-sizing: border-box;
			    }
			   \s
			    @media (min-width: 800px) {
			      .content {
			        max-width: 760px;
			      }
			    }
			   \s
			    /* Components */
			    a,
			    a:visited {
			      text-decoration: none;
			      color: #06f;
			    }
			   \s
			    a:hover {
			      text-decoration: underline;
			      color: #003c97;
			    }
			   \s
			    input[type="text"],
			    input[type="password"] {
			      height: auto;
			      width: 100%;
			      font-size: 1rem;
			      padding: 0.5rem;
			      box-sizing: border-box;
			    }
			   \s
			    button {
			      padding: 0.5rem 1rem;
			      font-size: 1.25rem;
			      line-height: 1.5;
			      border: none;
			      border-radius: 0.1rem;
			      width: 100%;
			    }
			   \s
			    button.primary {
			      color: #fff;
			      background-color: #06f;
			    }
			   \s
			    .alert {
			      padding: 0.75rem 1rem;
			      margin-bottom: 1rem;
			      line-height: 1.5;
			      border-radius: 0.1rem;
			      width: 100%;
			      box-sizing: border-box;
			      border-width: 1px;
			      border-style: solid;
			    }
			   \s
			    .alert.alert-danger {
			      color: #6b1922;
			      background-color: #f7d5d7;
			      border-color: #eab6bb;
			    }
			   \s
			    .alert.alert-success {
			      color: #145222;
			      background-color: #d1f0d9;
			      border-color: #c2ebcb;
			    }
			   \s
			    .screenreader {
			      position: absolute;
			      clip: rect(0 0 0 0);
			      height: 1px;
			      width: 1px;
			      padding: 0;
			      border: 0;
			      overflow: hidden;
			    }
			   \s
			    table {
			      width: 100%;
			      max-width: 100%;
			      margin-bottom: 2rem;
			    }
			   \s
			    .table-striped tr:nth-of-type(2n + 1) {
			      background-color: #e1e1e1;
			    }
			   \s
			    td {
			      padding: 0.75rem;
			      vertical-align: top;
			    }
			   \s
			    /* Login / logout layouts */
			    .login-form,
			    .logout-form {
			      max-width: 340px;
			      padding: 0 15px 15px 15px;
			      margin: 0 auto 2rem auto;
			      box-sizing: border-box;
			    }
			    </style>
			  </head>
			""";

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void getLoginWhenAutoConfigThenShowsDefaultLoginPage() throws Exception {
		this.spring.configLocations(this.xml("Simple")).autowire();
		// @formatter:off
		String expectedContent = "<!DOCTYPE html>\n"
				+ "<html lang=\"en\">\n"
				+ EXPECTED_HTML_HEAD
				+ "  <body>\n"
				+ "    <div class=\"content\">\n"
				+ "      <form class=\"login-form\" method=\"post\" action=\"/login\">\n"
				+ "        <h2>Please sign in</h2>\n"
				+ "        \n"
				+ "        <p>\n"
				+ "          <label for=\"username\" class=\"screenreader\">Username</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"username\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n"
				+ "        <p>\n"
				+ "          <label for=\"password\" class=\"screenreader\">Password</label>\n"
				+ "          <input type=\"password\" id=\"password\" name=\"password\" placeholder=\"Password\" required>\n"
				+ "        </p>\n"
				+ "\n"
				+ "\n"
				+ "        <button type=\"submit\" class=\"primary\">Sign in</button>\n"
				+ "      </form>\n"
				+ "\n"
				+ "\n"
				+ "    </div>\n"
				+ "  </body>\n"
				+ "</html>";
		// @formatter:on
		this.mvc.perform(get("/login")).andExpect(content().string(expectedContent));
	}

	@Test
	public void getLogoutWhenAutoConfigThenShowsDefaultLogoutPage() throws Exception {
		this.spring.configLocations(this.xml("AutoConfig")).autowire();
		this.mvc.perform(get("/logout")).andExpect(content().string(containsString("action=\"/logout\"")));
	}

	@Test
	public void getLoginWhenConfiguredWithCustomAttributesThenLoginPageReflects() throws Exception {
		this.spring.configLocations(this.xml("WithCustomAttributes")).autowire();
		// @formatter:off
		String expectedContent = "<!DOCTYPE html>\n"
				+ "<html lang=\"en\">\n"
				+ EXPECTED_HTML_HEAD
				+ "  <body>\n"
				+ "    <div class=\"content\">\n"
				+ "      <form class=\"login-form\" method=\"post\" action=\"/signin\">\n"
				+ "        <h2>Please sign in</h2>\n"
				+ "        \n"
				+ "        <p>\n"
				+ "          <label for=\"username\" class=\"screenreader\">Username</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"custom_user\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n"
				+ "        <p>\n"
				+ "          <label for=\"password\" class=\"screenreader\">Password</label>\n"
				+ "          <input type=\"password\" id=\"password\" name=\"custom_pass\" placeholder=\"Password\" required>\n"
				+ "        </p>\n"
				+ "\n"
				+ "\n"
				+ "        <button type=\"submit\" class=\"primary\">Sign in</button>\n"
				+ "      </form>\n"
				+ "\n"
				+ "\n"
				+ "    </div>\n"
				+ "  </body>\n"
				+ "</html>";
		// @formatter:on
		this.mvc.perform(get("/login")).andExpect(content().string(expectedContent));
		this.mvc.perform(get("/logout")).andExpect(status().is3xxRedirection());
	}

	@Test
	public void failedLoginWhenConfiguredWithCustomAuthenticationFailureThenForwardsAccordingly() throws Exception {
		this.spring.configLocations(this.xml("WithAuthenticationFailureForwardUrl")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "bob")
				.param("password", "invalidpassword");
		this.mvc.perform(loginRequest)
				.andExpect(status().isOk())
				.andExpect(forwardedUrl("/failure_forward_url"))
				.andExpect(request().attribute(WebAttributes.AUTHENTICATION_EXCEPTION, not(nullValue())));
		// @formatter:on
	}

	@Test
	public void successfulLoginWhenConfiguredWithCustomAuthenticationSuccessThenForwardsAccordingly() throws Exception {
		this.spring.configLocations(this.xml("WithAuthenticationSuccessForwardUrl")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password");
		this.mvc.perform(loginRequest)
				.andExpect(status().isOk())
				.andExpect(forwardedUrl("/success_forward_url"));
		// @formatter:on
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

}
