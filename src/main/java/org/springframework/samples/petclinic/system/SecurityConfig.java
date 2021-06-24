package org.springframework.samples.petclinic.system;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;

import java.net.MalformedURLException;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Value("${auth0.audience}")
	private String audience;

	@Value("${auth0.scope}")
	private String scope;

	@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
	private String issuer;

	@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
	private String jwks;

	@Value("${spring.security.oauth2.resourceserver.jwt.visma-connect-jose-type}")
	private String joseObjectType;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.mvcMatchers(HttpMethod.GET, "/api/menu/items/**").permitAll() // GET requests don't need auth
			.anyRequest()
			.authenticated()
			.and()
			.oauth2ResourceServer()
			.jwt()
			.decoder(jwtDecoder());
	}

	JwtDecoder jwtDecoder() throws MalformedURLException {
		OAuth2TokenValidator<Jwt> withAudience = new AudienceValidator(audience);
		OAuth2TokenValidator<Jwt> withScope = new ScopeValidator(scope);
		OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
		OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withAudience, withIssuer, withScope);

		NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder jwtDecoderBuilder = NimbusJwtDecoder.withJwkSetUri(jwks);
		jwtDecoderBuilder.jwtProcessorCustomizer(processor->{
			processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(joseObjectType)));
		});

		NimbusJwtDecoder jwtDecoder = jwtDecoderBuilder.build();
		jwtDecoder.setJwtValidator(validator);

		return jwtDecoder;
	}
}
