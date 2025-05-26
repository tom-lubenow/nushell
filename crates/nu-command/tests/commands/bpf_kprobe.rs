use nu_test_support::nu;

#[test]
fn help_lists_bpf_kprobe() {
    let actual = nu!("help commands | where name == bpf_kprobe | length");
    assert_eq!(actual.out, "1");
}
