use crate::{field, parse_fields, PolicyError};

pub const TESTLAB_WARNING: &str = "Selecting a regulatory country, including ALL, changes the driver-provided channel/DFS set and the maximum transmit power permitted by that country and the board calibration. The correct country is the user's responsibility. Frequencies and power cannot be overridden independently, and this validation does not establish legal operation or write NVRAM.";
pub const TESTLAB_CONFIRMATION: &str = "ACKNOWLEDGE_REGULATORY_AND_HARDWARE_RISK_V1";
const SUPPORTED_COUNTRIES: &str = "AD AF AG AI AL AM AN AR AS AT AU AW AZ BA BB BD BE BF BG BH BI BJ BM BO BR BS BW BY BZ CA CD CF CG CH CI CK CL CM CN CO CR CV CX CY CZ DE DK DM DO DZ EC EE EG EH ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GM GN GP GQ GR GT GU GW GY HK HN HR HT HU IE IL IM IN IO IQ IS IT JE JM JO JP KE KG KH KI KM KN KR KY KZ LA LB LC LI LK LR LS LT LU LV MA MC MD ME MF MG MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PR PT PW PY QA RE RO RS RW SA SC SE SG SI SK SL SM SN SR ST SV SZ TC TD TF TG TH TJ TL TM TN TR TT TW TZ UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestlabRequest {
    pub country: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedTestlabRequest(TestlabRequest);

impl TestlabRequest {
    pub fn from_country(country: &str) -> Result<Self, PolicyError> {
        if country != "ALL"
            && !SUPPORTED_COUNTRIES
                .split_ascii_whitespace()
                .any(|code| code == country)
        {
            return Err(PolicyError::InvalidValue("country code"));
        }
        Ok(Self {
            country: country.to_owned(),
        })
    }

    pub fn parse(input: &str) -> Result<Self, PolicyError> {
        const FIELDS: [&str; 1] = ["country"];
        let values = parse_fields(input, 64, FIELDS)?;
        if values.len() != FIELDS.len() {
            return Err(PolicyError::Missing("testlab request field"));
        }
        let country = field(&values, "country")?;
        Self::from_country(country)
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
        for country in ["", "D", "de", "DE/01", "#a", "A1", "AAAA", "ZZ"] {
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
