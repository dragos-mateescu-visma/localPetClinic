package org.springframework.samples.petclinic.system;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.util.List;

public class ScopeValidator implements OAuth2TokenValidator<Jwt> {
	private final String scope;

	ScopeValidator(String scope) {
		Assert.hasText(scope, "scope is null or empty");
		this.scope = scope;
	}

	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		List<String> scopes = jwt.getClaim("scope");
		if (scopes.contains(this.scope)) {
			return OAuth2TokenValidatorResult.success();
		}
		OAuth2Error err = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN);
		return OAuth2TokenValidatorResult.failure(err);
	}
}
