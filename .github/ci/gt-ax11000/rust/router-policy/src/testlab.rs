use crate::{field, parse_fields, PolicyError};

pub const TESTLAB_WARNING: &str = "Selecting a regulatory country, including ALL, changes the driver-provided channel/DFS set and the maximum transmit power permitted by that country and the board calibration. The correct country is the user's responsibility. Frequencies and power cannot be overridden independently, and this validation does not establish legal operation or write NVRAM.";
pub const TESTLAB_CONFIRMATION: &str = "ACKNOWLEDGE_REGULATORY_AND_HARDWARE_RISK_V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestlabRequest {
    pub country: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedTestlabRequest(TestlabRequest);

impl TestlabRequest {
    pub fn parse(input: &str) -> Result<Self, PolicyError> {
        const FIELDS: [&str; 1] = ["country"];
        let values = parse_fields(input, 64, FIELDS)?;
        if values.len() != FIELDS.len() {
            return Err(PolicyError::Missing("testlab request field"));
        }
        let country = field(&values, "country")?;
        if country != "ALL"
            && !(country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase()))
        {
            return Err(PolicyError::InvalidValue("country code"));
        }
        Ok(Self {
            country: country.to_owned(),
        })
    }

    pub fn warning(&self) -> &'static str {
        TESTLAB_WARNING
    }

    /// Produce a capability-like value only after an exact, versioned consent.
    /// No part of this crate applies or persists the request.
    pub fn authorize(self, confirmation: &str) -> Result<AuthorizedTestlabRequest, PolicyError> {
        if confirmation != TESTLAB_CONFIRMATION {
            return Err(PolicyError::ConfirmationRequired);
        }
        Ok(AuthorizedTestlabRequest(self))
    }
}

impl AuthorizedTestlabRequest {
    pub fn request(&self) -> &TestlabRequest {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST: &str = "country=AU";

    #[test]
    fn explicit_warning_and_exact_confirmation_are_mandatory() {
        let request = TestlabRequest::parse(REQUEST).unwrap();
        assert!(request
            .warning()
            .contains("cannot be overridden independently"));
        for invalid in [
            "",
            "yes",
            "ACKNOWLEDGE_REGULATORY_AND_HARDWARE_RISK",
            "acknowledge_regulatory_and_hardware_risk_v1",
        ] {
            assert_eq!(
                request.clone().authorize(invalid),
                Err(PolicyError::ConfirmationRequired)
            );
        }
        assert_eq!(
            request
                .clone()
                .authorize(TESTLAB_CONFIRMATION)
                .unwrap()
                .request(),
            &request
        );
    }

    #[test]
    fn country_boundary_includes_explicit_all_domain() {
        for country in ["DE", "AU", "ALL"] {
            assert!(TestlabRequest::parse(&format!("country={country}")).is_ok());
        }
        for country in ["", "D", "de", "DE/01", "#a", "A1", "AAAA"] {
            let input = format!("country={country}");
            assert!(TestlabRequest::parse(&input).is_err(), "accepted {country}");
        }
    }

    #[test]
    fn independent_frequency_power_and_duplicate_fields_are_rejected() {
        for value in [
            "country=AU;tx_power_mw=100",
            "country=AU;allow_dfs=true",
            "country=AU;allow_all_channels=true",
            "country=AU;country=DE",
        ] {
            assert!(TestlabRequest::parse(value).is_err(), "accepted {value}");
        }
    }
}
