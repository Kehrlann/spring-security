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

package org.springframework.security.web.server.ui;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import reactor.core.publisher.Mono;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.security.web.util.CssUtils;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * Generates a default log in page used for authenticating users.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class LoginPageGeneratingWebFilter implements WebFilter {

	private ServerWebExchangeMatcher matcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/login");

	private Map<String, String> oauth2AuthenticationUrlToClientName = new HashMap<>();

	private boolean formLoginEnabled;

	public void setFormLoginEnabled(boolean enabled) {
		this.formLoginEnabled = enabled;
	}

	public void setOauth2AuthenticationUrlToClientName(Map<String, String> oauth2AuthenticationUrlToClientName) {
		Assert.notNull(oauth2AuthenticationUrlToClientName, "oauth2AuthenticationUrlToClientName cannot be null");
		this.oauth2AuthenticationUrlToClientName = oauth2AuthenticationUrlToClientName;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.matcher.matches(exchange)
			.filter(ServerWebExchangeMatcher.MatchResult::isMatch)
			.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
			.flatMap((matchResult) -> render(exchange));
	}

	private Mono<Void> render(ServerWebExchange exchange) {
		ServerHttpResponse result = exchange.getResponse();
		result.setStatusCode(HttpStatus.OK);
		result.getHeaders().setContentType(MediaType.TEXT_HTML);
		return result.writeWith(createBuffer(exchange));
	}

	private Mono<DataBuffer> createBuffer(ServerWebExchange exchange) {
		Mono<CsrfToken> token = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
		return token.map(LoginPageGeneratingWebFilter::csrfToken).defaultIfEmpty("").map((csrfTokenHtmlInput) -> {
			byte[] bytes = createPage(exchange, csrfTokenHtmlInput);
			DataBufferFactory bufferFactory = exchange.getResponse().bufferFactory();
			return bufferFactory.wrap(bytes);
		});
	}

	private byte[] createPage(ServerWebExchange exchange, String csrfTokenHtmlInput) {
		MultiValueMap<String, String> queryParams = exchange.getRequest().getQueryParams();
		String contextPath = exchange.getRequest().getPath().contextPath().value();

		return HtmlTemplates.fromTemplate(LOGIN_PAGE_TEMPLATE)
			.withRawHtml("cssStyle", CssUtils.getCssStyleBlock())
			.withRawHtml("formLogin", formLogin(queryParams, contextPath, csrfTokenHtmlInput))
			.withRawHtml("oauth2Login", oauth2Login(queryParams, contextPath, this.oauth2AuthenticationUrlToClientName))
			.render()
			.getBytes(Charset.defaultCharset());
	}

	private String formLogin(MultiValueMap<String, String> queryParams, String contextPath, String csrfTokenHtmlInput) {
		if (!this.formLoginEnabled) {
			return "";
		}

		boolean isError = queryParams.containsKey("error");
		boolean isLogoutSuccess = queryParams.containsKey("logout");

		return HtmlTemplates.fromTemplate(LOGIN_FORM_TEMPLATE)
			.withValue("loginUrl", contextPath + "/login")
			.withRawHtml("errorMessage", createError(isError))
			.withRawHtml("logoutMessage", createLogoutSuccess(isLogoutSuccess))
			.withRawHtml("csrf", csrfTokenHtmlInput)
			.render();
	}

	private static String oauth2Login(MultiValueMap<String, String> queryParams, String contextPath,
			Map<String, String> oauth2AuthenticationUrlToClientName) {
		if (oauth2AuthenticationUrlToClientName.isEmpty()) {
			return "";
		}
		boolean isError = queryParams.containsKey("error");

		String oauth2Rows = oauth2AuthenticationUrlToClientName.entrySet()
			.stream()
			.map((urlToName) -> oauth2LoginLink(contextPath, urlToName.getKey(), urlToName.getValue()))
			.collect(Collectors.joining("\n"));
		return HtmlTemplates.fromTemplate(OAUTH2_LOGIN_TEMPLATE)
			.withRawHtml("errorMessage", createError(isError))
			.withRawHtml("oauth2Rows", oauth2Rows)
			.render();
	}

	private static String oauth2LoginLink(String contextPath, String url, String clientName) {
		return HtmlTemplates.fromTemplate(OAUTH2_ROW_TEMPLATE)
			.withValue("url", contextPath + url)
			.withValue("clientName", clientName)
			.render();
	}

	private static String csrfToken(CsrfToken token) {
		return HtmlTemplates.fromTemplate(CSRF_INPUT_TEMPLATE)
			.withValue("name", token.getParameterName())
			.withValue("value", token.getToken())
			.render();
	}

	private static String createError(boolean isError) {
		return isError ? "<div class=\"alert alert-danger\" role=\"alert\">Invalid credentials</div>" : "";
	}

	private static String createLogoutSuccess(boolean isLogoutSuccess) {
		return isLogoutSuccess ? "<div class=\"alert alert-success\" role=\"alert\">You have been signed out</div>"
				: "";
	}

	private static final String LOGIN_PAGE_TEMPLATE = """
			<!DOCTYPE html>
			<html lang="en">
				<head>
					<meta charset="utf-8">
					<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
					<meta name="description" content="">
					<meta name="author" content="">
					<title>Please sign in</title>
			{{cssStyle}}
				</head>
				<body>
					<div class="content">
			{{formLogin}}
			{{oauth2Login}}
					</div>
				</body>
			</html>""";

	private static final String LOGIN_FORM_TEMPLATE = """
						<form class="login-form" method="post" action="{{loginUrl}}">
							<h2>Please sign in</h2>
			{{errorMessage}}{{logoutMessage}}
							<p>
								<label for="username" class="screenreader">Username</label>
								<input type="text" id="username" name="username" placeholder="Username" required autofocus>
							</p>
							<p>
								<label for="password" class="screenreader">Password</label>
								<input type="password" id="password" name="password" placeholder="Password" required>
							</p>
			{{csrf}}
							<button type="submit" class="primary">Sign in</button>
						</form>""";

	private static final String CSRF_INPUT_TEMPLATE = """
			<input name="{{name}}" type="hidden" value="{{value}}" />
			""";

	private static final String OAUTH2_LOGIN_TEMPLATE = """
			<h2>Login with OAuth 2.0</h2>
			{{errorMessage}}
			<table class="table table-striped">
			{{oauth2Rows}}
			</table>""";

	private static final String OAUTH2_ROW_TEMPLATE = """
			\t<tr><td><a href="{{url}}">{{clientName}}</a></td></tr>""";

}
