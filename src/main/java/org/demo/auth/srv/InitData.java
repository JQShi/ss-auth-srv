package org.demo.auth.srv;

import java.time.Duration;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;

@Component
public class InitData implements ApplicationRunner {

	private final Logger logger = LoggerFactory.getLogger(getClass());

	private static final String INIT_OAUTH2_REGISTERED_CLIENT = "CREATE TABLE oauth2_registered_client (\r\n"
			+ "    id varchar(100) NOT NULL,\r\n" + "    client_id varchar(100) NOT NULL,\r\n"
			+ "    client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,\r\n"
			+ "    client_secret varchar(200) DEFAULT NULL,\r\n"
			+ "    client_secret_expires_at timestamp DEFAULT NULL,\r\n" + "    client_name varchar(200) NOT NULL,\r\n"
			+ "    client_authentication_methods varchar(1000) NOT NULL,\r\n"
			+ "    authorization_grant_types varchar(1000) NOT NULL,\r\n"
			+ "    redirect_uris varchar(1000) DEFAULT NULL,\r\n" + "    scopes varchar(1000) NOT NULL,\r\n"
			+ "    client_settings varchar(2000) NOT NULL,\r\n" + "    token_settings varchar(2000) NOT NULL,\r\n"
			+ "    PRIMARY KEY (id)\r\n" + ")";

	private static final String INIT_OAUTH2_AUTHORIZATION_CONSENT = "CREATE TABLE oauth2_authorization_consent (\r\n"
			+ "    registered_client_id varchar(100) NOT NULL,\r\n" + "    principal_name varchar(200) NOT NULL,\r\n"
			+ "    authorities varchar(1000) NOT NULL,\r\n"
			+ "    PRIMARY KEY (registered_client_id, principal_name)\r\n" + ")";

	private static final String INIT_OAUTH2_AUTHORIZATION = "CREATE TABLE oauth2_authorization (\r\n"
			+ "    id varchar(100) NOT NULL,\r\n" + "    registered_client_id varchar(100) NOT NULL,\r\n"
			+ "    principal_name varchar(200) NOT NULL,\r\n"
			+ "    authorization_grant_type varchar(100) NOT NULL,\r\n"
			+ "    authorized_scopes varchar(1000) DEFAULT NULL,\r\n" + "    attributes blob DEFAULT NULL,\r\n"
			+ "    state varchar(500) DEFAULT NULL,\r\n" + "    authorization_code_value blob DEFAULT NULL,\r\n"
			+ "    authorization_code_issued_at timestamp DEFAULT NULL,\r\n"
			+ "    authorization_code_expires_at timestamp DEFAULT NULL,\r\n"
			+ "    authorization_code_metadata blob DEFAULT NULL,\r\n" + "    access_token_value blob DEFAULT NULL,\r\n"
			+ "    access_token_issued_at timestamp DEFAULT NULL,\r\n"
			+ "    access_token_expires_at timestamp DEFAULT NULL,\r\n"
			+ "    access_token_metadata blob DEFAULT NULL,\r\n"
			+ "    access_token_type varchar(100) DEFAULT NULL,\r\n"
			+ "    access_token_scopes varchar(1000) DEFAULT NULL,\r\n"
			+ "    oidc_id_token_value blob DEFAULT NULL,\r\n"
			+ "    oidc_id_token_issued_at timestamp DEFAULT NULL,\r\n"
			+ "    oidc_id_token_expires_at timestamp DEFAULT NULL,\r\n"
			+ "    oidc_id_token_metadata blob DEFAULT NULL,\r\n" + "    refresh_token_value blob DEFAULT NULL,\r\n"
			+ "    refresh_token_issued_at timestamp DEFAULT NULL,\r\n"
			+ "    refresh_token_expires_at timestamp DEFAULT NULL,\r\n"
			+ "    refresh_token_metadata blob DEFAULT NULL,\r\n" + "    PRIMARY KEY (id)\r\n" + ")";

	private static final String INIT_USERS = "create table users(username varchar_ignorecase(50) not null primary key,password varchar_ignorecase(500) not null,enabled boolean not null)";
	
	private static final String INIT_AUTHORITIES = "create table authorities (username varchar_ignorecase(50) not null,authority varchar_ignorecase(50) not null,constraint fk_authorities_users foreign key(username) references users(username))";

	@Override
	public void run(ApplicationArguments args) throws Exception {
		this.jdbcTemplate.execute(INIT_OAUTH2_REGISTERED_CLIENT);
		this.jdbcTemplate.execute(INIT_OAUTH2_AUTHORIZATION_CONSENT);
		this.jdbcTemplate.execute(INIT_OAUTH2_AUTHORIZATION);
		this.jdbcTemplate.execute(INIT_USERS);
		this.jdbcTemplate.execute(INIT_AUTHORITIES);
		
		@SuppressWarnings("deprecation")
		UserDetails userDetails = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
		.build();
		userDetailsService.createUser(userDetails);
		
		
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
		.clientId("messaging-client").clientSecret("{noop}secret")
		.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
		.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
		.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
		.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//		.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
		.redirectUri("https://cn.bing.com").scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
		.scope(OidcScopes.EMAIL).scope(OidcScopes.ADDRESS).scope(OidcScopes.PHONE).scope("message.read")
		.scope("message.write")
//		.redirectUri("http://127.0.0.1:8080/authorized").scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
//		.scope(OidcScopes.EMAIL).scope(OidcScopes.ADDRESS).scope(OidcScopes.PHONE).scope("message.read")
//		.scope("message.write")
		.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1L)).build())
		.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();
		
		registeredClientRepository.save(registeredClient);
		
		this.logger.info("Tables init done");
	}

	@Autowired
	private JdbcTemplate jdbcTemplate;
	
	@Autowired
	private UserDetailsManager userDetailsService;
	
	@Autowired
	private RegisteredClientRepository registeredClientRepository;

}
