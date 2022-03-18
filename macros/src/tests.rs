use super::*;

fn get_text(output: &proc_macro2::TokenStream) -> Result<String> {
    // Format the file with rustfmt.
    let content = rustfmt_wrapper::rustfmt(output).unwrap();

    // Add newlines after end-braces at <= two levels of indentation.
    Ok(if cfg!(not(windows)) {
        let regex = regex::Regex::new(r#"(})(\n\s{0,8}[^} ])"#).unwrap();
        regex.replace_all(&content, "$1\n$2").to_string()
    } else {
        let regex = regex::Regex::new(r#"(})(\r\n\s{0,8}[^} ])"#).unwrap();
        regex.replace_all(&content, "$1\r\n$2").to_string()
    })
}

#[test]
fn test_crud_gen() {
    let mut actual = do_gen(
        quote! {
            tag = "disks",
        },
        quote! {
            #[derive(Parser, Debug, Clone)]
            enum SubCommand {
                Attach(CmdDiskAttach),
                Create(CmdDiskCreate),
                Detach(CmdDiskDetach),
                Edit(CmdDiskEdit),
                View(CmdDiskView),
            }
        },
    )
    .unwrap();

    expectorate::assert_contents("gen/disks.rs", &get_text(&actual).unwrap());

    actual = do_gen(
        quote! {
            tag = "organizations",
        },
        quote! {
            #[derive(Parser, Debug, Clone)]
            enum SubCommand {}
        },
    )
    .unwrap();

    expectorate::assert_contents("gen/organizations.rs", &get_text(&actual).unwrap());

    actual = do_gen(
        quote! {
            tag = "subnets",
        },
        quote! {
            #[derive(Parser, Debug, Clone)]
            enum SubCommand {}
        },
    )
    .unwrap();

    expectorate::assert_contents("gen/subnets.rs", &get_text(&actual).unwrap());
}
