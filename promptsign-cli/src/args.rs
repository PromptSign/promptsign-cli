// Minimal argument parser matching node:util parseArgs semantics used by the
// reference CLI: --opt value, --opt=value, boolean flags, positionals.

use std::collections::{HashMap, HashSet};

pub struct Parsed {
    pub values: HashMap<String, String>,
    pub flags: HashSet<String>,
    pub positionals: Vec<String>,
}

pub fn parse(args: &[String], string_opts: &[&str], bool_opts: &[&str]) -> Result<Parsed, String> {
    let mut values = HashMap::new();
    let mut flags = HashSet::new();
    let mut positionals = Vec::new();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];

        if let Some(name) = arg.strip_prefix("--") {
            let (name, inline) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (name, None),
            };

            if bool_opts.contains(&name) {
                if inline.is_some() {
                    return Err(format!("option '--{name}' does not take a value"));
                }
                flags.insert(name.to_string());
            } else if string_opts.contains(&name) {
                let value = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        args.get(i)
                            .cloned()
                            .ok_or_else(|| format!("option '--{name}' requires a value"))?
                    }
                };

                values.insert(name.to_string(), value);
            } else {
                return Err(format!("unknown option '--{name}'"));
            }
        } else {
            positionals.push(arg.clone());
        }
        i += 1;
    }
    Ok(Parsed {
        values,
        flags,
        positionals,
    })
}
