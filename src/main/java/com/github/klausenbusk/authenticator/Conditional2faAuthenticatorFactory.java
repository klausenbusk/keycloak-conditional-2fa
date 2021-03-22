package com.github.klausenbusk.authenticator;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.models.AuthenticationExecutionModel;

public class Conditional2faAuthenticatorFactory implements ConditionalAuthenticatorFactory {
	public static final String PROVIDER_ID = "conditional-user-2fa";
	protected static final String CONDITIONAL_USER_ROLE = "condUserRole";

	private static final Requirement[] REQUIREMENT_CHOICES = { AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.DISABLED };

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

	static {
		ProviderConfigProperty property = new ProviderConfigProperty();
		property.setName(CONDITIONAL_USER_ROLE);
		property.setLabel("User role");
		property.setHelpText(
				"Role the user should have to execute this flow if 2FA (OTP or WebAuthn) isn't configured for the user. Click 'Select Role' button to browse roles, or just type it in the textbox. To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole");
		property.setType(ProviderConfigProperty.ROLE_TYPE);

		configProperties.add(property);
	}

	@Override
	public void init(Scope config) {
		// no-op
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
		// no-op
	}

	@Override
	public void close() {
		// no-op
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return "Condition - user 2fa";
	}

	@Override
	public String getReferenceCategory() {
		return "condition";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public String getHelpText() {
		return "Flow is executed only if user has 2FA (OTP or WebAuthn) configured or the user has the given role.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	public ConditionalAuthenticator getSingleton() {
		return Conditional2faAuthenticator.SINGLETON;
	}
}
