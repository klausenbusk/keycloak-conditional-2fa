package com.github.klausenbusk.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalRoleAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.jboss.logging.Logger;

public class Conditional2faAuthenticator implements ConditionalAuthenticator {
	public static final Conditional2faAuthenticator SINGLETON = new Conditional2faAuthenticator();
	private static final Logger logger = Logger.getLogger(ConditionalRoleAuthenticator.class);

	public static void main(String[] args) {
		System.out.println("Hello World!");
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		// Not used
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		// Not used
	}

	@Override
	public void close() {
		// Not used
	}

	@Override
	public boolean matchCondition(AuthenticationFlowContext context) {
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		RealmModel realm = context.getRealm();

		// If OTP or WebAuthn is configured
		if (session.userCredentialManager().getStoredCredentialsByTypeStream(realm, user, OTPCredentialModel.TYPE)
				.count() > 0
				|| session.userCredentialManager()
						.getStoredCredentialsByTypeStream(realm, user, WebAuthnCredentialModel.TYPE_TWOFACTOR)
						.count() > 0) {
			return true;
		}

		// From:
		// https://github.com/keycloak/keycloak/blob/12.0.4/services/src/main/java/org/keycloak/authentication/authenticators/conditional/ConditionalRoleAuthenticator.java#L16-L31
		AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();
		if (authConfig != null && authConfig.getConfig() != null) {
			String requiredRole = authConfig.getConfig().get(Conditional2faAuthenticatorFactory.CONDITIONAL_USER_ROLE);
			RoleModel role = KeycloakModelUtils.getRoleFromString(realm, requiredRole);
			// fail-open
			if (role == null) {
				logger.errorv("Invalid role name submitted: {0}", requiredRole);
				// Fail closed
				return true;
			}
			return user.hasRole(role);
		}
		return false;
	}
}
