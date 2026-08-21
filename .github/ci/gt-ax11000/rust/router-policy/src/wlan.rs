use crate::{field, parse_fields, PolicyError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authentication {
    Wpa2Personal,
    Wpa3Sae,
    Wpa2Wpa3Transition,
    Wep,
    Open,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cipher {
    AesCcmp,
    Tkip,
    TkipAndAes,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedManagementFrames {
    Disabled,
    Optional,
    Required,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WlanSecurityTuple {
    pub authentication: Authentication,
    pub cipher: Cipher,
    pub pmf: ProtectedManagementFrames,
    pub wps_enabled: bool,
}

impl WlanSecurityTuple {
    /// Parse `auth=...;cipher=...;pmf=...;wps=...` without accepting aliases.
    pub fn parse(input: &str) -> Result<Self, PolicyError> {
        const FIELDS: [&str; 4] = ["auth", "cipher", "pmf", "wps"];
        let values = parse_fields(input, 256, FIELDS)?;
        if values.len() != FIELDS.len() {
            return Err(PolicyError::Missing("WLAN security field"));
        }
        Ok(Self {
            authentication: match field(&values, "auth")? {
                "wpa2-personal" => Authentication::Wpa2Personal,
                "wpa3-sae" => Authentication::Wpa3Sae,
                "wpa2-wpa3-transition" => Authentication::Wpa2Wpa3Transition,
                "wep" => Authentication::Wep,
                "open" => Authentication::Open,
                _ => return Err(PolicyError::InvalidValue("WLAN authentication")),
            },
            cipher: match field(&values, "cipher")? {
                "aes-ccmp" => Cipher::AesCcmp,
                "tkip" => Cipher::Tkip,
                "tkip+aes" => Cipher::TkipAndAes,
                "none" => Cipher::None,
                _ => return Err(PolicyError::InvalidValue("WLAN cipher")),
            },
            pmf: match field(&values, "pmf")? {
                "disabled" => ProtectedManagementFrames::Disabled,
                "optional" => ProtectedManagementFrames::Optional,
                "required" => ProtectedManagementFrames::Required,
                _ => return Err(PolicyError::InvalidValue("PMF")),
            },
            wps_enabled: match field(&values, "wps")? {
                "off" => false,
                "on" => true,
                _ => return Err(PolicyError::InvalidValue("WPS")),
            },
        })
    }

    pub fn validate(self) -> Result<(), PolicyError> {
        if self.cipher != Cipher::AesCcmp {
            return Err(PolicyError::Invariant("WEP/TKIP/open cipher prohibited"));
        }
        if self.wps_enabled {
            return Err(PolicyError::Invariant("WPS prohibited"));
        }
        match self.authentication {
            Authentication::Wpa2Personal => {
                if self.pmf == ProtectedManagementFrames::Disabled {
                    return Err(PolicyError::Invariant("WPA2 requires PMF capability"));
                }
            }
            Authentication::Wpa3Sae => {
                if self.pmf != ProtectedManagementFrames::Required || self.wps_enabled {
                    return Err(PolicyError::Invariant("WPA3-SAE requires PMF and no WPS"));
                }
            }
            Authentication::Wpa2Wpa3Transition => {
                if self.pmf == ProtectedManagementFrames::Disabled || self.wps_enabled {
                    return Err(PolicyError::Invariant(
                        "transition mode requires PMF and no WPS",
                    ));
                }
            }
            Authentication::Wep | Authentication::Open => {
                return Err(PolicyError::Invariant("WEP/open authentication prohibited"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(auth: &str, cipher: &str, pmf: &str, wps: &str) -> WlanSecurityTuple {
        WlanSecurityTuple::parse(&format!("auth={auth};cipher={cipher};pmf={pmf};wps={wps}"))
            .unwrap()
    }

    #[test]
    fn hardened_default_accepts_wpa2_aes_and_wpa3_sae() {
        for value in [
            tuple("wpa2-personal", "aes-ccmp", "optional", "off"),
            tuple("wpa2-personal", "aes-ccmp", "required", "off"),
            tuple("wpa3-sae", "aes-ccmp", "required", "off"),
        ] {
            value.validate().unwrap();
        }
    }

    #[test]
    fn every_wep_tkip_and_open_combination_fails() {
        for auth in ["wep", "open", "wpa2-personal", "wpa3-sae"] {
            for cipher in ["tkip", "tkip+aes", "none"] {
                for pmf in ["disabled", "optional", "required"] {
                    assert!(
                        tuple(auth, cipher, pmf, "off").validate().is_err(),
                        "accepted {auth}/{cipher}/{pmf}"
                    );
                }
            }
        }
    }

    #[test]
    fn wpa3_requires_pmf_and_forbids_wps() {
        for pmf in ["disabled", "optional"] {
            assert!(tuple("wpa3-sae", "aes-ccmp", pmf, "off")
                .validate()
                .is_err());
        }
        assert!(tuple("wpa3-sae", "aes-ccmp", "required", "on")
            .validate()
            .is_err());
    }

    #[test]
    fn transition_is_supported_but_wps_has_no_exception() {
        let transition = tuple("wpa2-wpa3-transition", "aes-ccmp", "optional", "off");
        transition.validate().unwrap();

        let wps = tuple("wpa2-personal", "aes-ccmp", "optional", "on");
        assert!(wps.validate().is_err());
    }

    #[test]
    fn parser_is_closed_to_aliases_unknowns_and_partial_tuples() {
        for value in [
            "auth=wpa3;cipher=aes-ccmp;pmf=required;wps=off",
            "auth=wpa3-sae;cipher=aes;pmf=required;wps=off",
            "auth=wpa3-sae;cipher=aes-ccmp;pmf=on;wps=off",
            "auth=wpa3-sae;cipher=aes-ccmp;pmf=required",
            "auth=wpa3-sae;cipher=aes-ccmp;pmf=required;wps=off;x=y",
        ] {
            assert!(WlanSecurityTuple::parse(value).is_err(), "accepted {value}");
        }
    }
}
