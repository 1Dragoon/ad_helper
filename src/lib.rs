use anyhow::{bail, Error, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::NaiveDateTime;
use itertools::Itertools;
use ldap3::{Ldap, LdapConnAsync, SearchEntry};
use std::{borrow::Cow, fmt::Display, time::Duration};
use trust_dns_resolver::TokioAsyncResolver;

pub async fn autoconnect_ldap(timeout: Option<Duration>) -> Result<Ldap, anyhow::Error> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let lookup = resolver.srv_lookup("_ldap._tcp").await?;
    let records = lookup
        .into_iter()
        .sorted_by(|srv_a, srv_b| srv_a.priority().cmp(&srv_b.priority()))
        .collect::<Vec<_>>();
    let mut recs_iter = records.iter();
    loop {
        if let Some(srv) = recs_iter.next() {
            let mut server = srv.target().to_string();
            if server.ends_with('.') {
                server.truncate(server.len() - 1);
            }
            let url = format!("ldaps://{server}:636");
            match LdapConnAsync::new(url.as_str()).await {
                Ok((conn, mut ldap)) => {
                    if let Some(first_label) = srv.target().iter().next() {
                        if let Ok(host) = std::str::from_utf8(first_label) {
                            ldap3::drive!(conn);
                            if let Some(time) = timeout {
                                ldap.with_timeout(time);
                            }
                            if let Err(err) = ldap.sasl_gssapi_bind(host).await {
                                bail!("Failed to authenticate to AD\nReason: {err}")
                            }
                            break Ok(ldap);
                        } else {
                            continue;
                        }
                    }
                }
                Err(err) => {
                    println!("Error: {server} {err}\nTrying a different server...");
                    continue;
                }
            };
        } else {
            bail!("Couldn't find an appropriate domain controller to connect to.");
        }
    }
}

pub fn generate_bulk_filter<
    'a,
    S: Into<Cow<'a, str>> + Display,
    T: Into<Cow<'a, str>> + Display,
    U: Into<Cow<'a, str>> + Display,
>(
    set: &[S],
    category: T,
    attribute: U,
) -> String {
    let mut filter = format!("(&(objectCategory={category})(|");
    set.iter().for_each(|n| {
        filter.push_str(format!("({attribute}={})", n).as_str());
    });
    filter.push_str("))");
    filter
}

pub trait AttributeHelper<'a> {
    fn int_attr(&self, attr_name: &str) -> Option<i64>;
    fn enabled(&self) -> bool;
    fn last_logon(&self) -> NaiveDateTime;
    fn str_attr(&'a mut self, name: &str) -> Option<String>;
    fn sid(&self) -> Result<String, anyhow::Error>;
    fn member_of(&'a mut self) -> Option<Vec<String>>;
}

impl<'a> AttributeHelper<'a> for SearchEntry {
    fn member_of(&mut self) -> Option<Vec<String>> {
        Some(
            self.attrs
                .remove("memberOf")?
                .into_iter()
                .collect::<Vec<_>>(),
        )
    }

    fn int_attr(&self, name: &str) -> Option<i64> {
        self.attrs
            .get(name)?
            .get(0)
            .unwrap_or(&"0".to_string())
            .parse::<i64>()
            .ok()
    }

    fn str_attr(&mut self, name: &str) -> Option<String> {
        Some(self.attrs.remove(name)?.remove(0))
    }

    fn enabled(&self) -> bool {
        // Default to disabled (2)
        self.int_attr("userAccountControl").unwrap_or(2) & 2 == 0
        // bitwise and the uac number with 2; if it equals zero, the account is enabled
    }

    fn last_logon(&self) -> NaiveDateTime {
        let last_logon = self.int_attr("lastLogonTimestamp").unwrap_or_default();
        NaiveDateTime::from_timestamp(
            (((last_logon as f64 / 10000000.0) as u64)
                .saturating_sub(11644473600u64)
                .saturating_sub(7 * 3600)) as _,
            0,
        )
    }

    fn sid(&self) -> Result<String, anyhow::Error> {
        let default = Vec::new();
        obj_sid_to_string(
            self.bin_attrs
                .get("objectSid")
                .map(|a| a.get(0).unwrap_or(&default))
                .unwrap_or(&default),
        )
    }
}

fn obj_sid_to_string(bytes: &[u8]) -> Result<String, anyhow::Error> {
    let max_identifier_authority = 6;
    let max_sub_authorities = 15;
    let subauth_size = 4; // each subauth is 32-bits

    // The revision number is an unsigned 8-bit unsigned integer.
    if let Some(revision) = bytes.get(0) {
        // The number of sub-authority parts is specified as an 8-bit unsigned integer.
        let subauth_count = bytes[*revision as usize] as usize;

        if subauth_count > max_sub_authorities {
            bail!("SID exceeds the maximum number of sub authorities of {max_sub_authorities}")
        }

        let min_binary_length = *revision as usize + 1 + max_identifier_authority; // Revision (1) + subauth count (1) + identifier authority maximum (6)
        let max_binary_length = min_binary_length + (subauth_count * subauth_size);

        if bytes.len() < min_binary_length {
            bail!("SID array doesn't meet the minimum size requirement.")
        }

        if bytes.len() != max_binary_length {
            bail!("According to byte {revision} of the SID its total length should be ({min_binary_length} + {subauth_size} * {subauth_count}) bytes, however its actual length is {} bytes.)", bytes.len());
        }
        // The powershell SID string doesn't appear to use the authority, so commented it out for now
        // The authority is a 48-bit unsigned integer stored in big-endian format.
        // let by = bytes.to_vec();
        // let authority = by.as_slice().read_u48::<BigEndian>()?; // let authority = ByteBuffer.wrap(bytes).getLong() & mask_48_bit;

        let mut sid_str = "S-".to_owned();
        sid_str.push_str(revision.to_string().as_str());
        sid_str.push('-');
        sid_str.push_str(subauth_count.to_string().as_str());
        // sid_str.push('-');
        // sid_str.push_str(authority.to_string().as_str());

        // The sub-authority consists of up to 255 32-bit unsigned integers in little-endian format. The number of integers is specified by numberOfSubAuthorityParts.
        bytes[min_binary_length..bytes.len()]
            .chunks_exact(subauth_size)
            .into_iter()
            .map(|mut a| a.read_u32::<LittleEndian>().unwrap_or_default())
            .for_each(|sub_authority_part| {
                sid_str.push('-');
                sid_str.push_str(sub_authority_part.to_string().as_str());
            });
        Ok(sid_str)
    } else {
        Err(Error::msg("Couldn't get revision from SID"))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
