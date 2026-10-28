//! The installer runs under macOS's bash 3.2, which under sudo (C locale)
//! reads a byte of a non-ASCII character right after `$NAME` as part of the
//! variable name and stops with "NAME?: unbound variable". Its code (not its
//! comments) stays ASCII.

#[test]
fn installer_code_is_ascii() {
    let text = include_str!("../../../deploy/install.sh");
    for (n, line) in text.lines().enumerate() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        assert!(
            line.is_ascii(),
            "deploy/install.sh:{}: non-ASCII outside a comment: {line}",
            n + 1
        );
    }
}
