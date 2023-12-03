package com.aplussoft.springjwtauth.config;



import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpHeaders;

@ConfigurationProperties(prefix = "application.jwt")
public class CustomPropertiesConfig {

	private String secretKeyString;
	private Long expiration;
	private String tokenPrefix;

	

	public CustomPropertiesConfig() {
	}

	public String getSecretKeyString() {
		return secretKeyString;
	}

	public void setSecretKeyString(String secretKeyString) {
		this.secretKeyString = secretKeyString;
	}

	public Long getExpiration() {
		return expiration;
	}

	public void setExpiration(Long expiration) {
		this.expiration = expiration;
	}

	 public String getTokenPrefix() {
		return tokenPrefix;
	}

	public void setTokenPrefix(String tokenPrefix) {
		this.tokenPrefix = tokenPrefix;
	}

	public String getAuthorizationHeader() {
		return HttpHeaders.AUTHORIZATION;
	}
	

}
