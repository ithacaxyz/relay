use std::env;
use xshell::{Shell, cmd};

mod flags;

fn main() -> anyhow::Result<()> {
    let flags = flags::Xtask::from_env_or_exit();
    match flags.subcommand {
        flags::XtaskCmd::E2e(flags::E2e { rest }) => {
            let sh = Shell::new()?;

            // Change to the tests/account directory to build contracts
            let account_dir = "tests/account";
            let _dir = sh.push_dir(account_dir);

            println!("Building contracts...");

            // Run the forge build commands as specified in the README
            cmd!(sh, "forge build").run()?;
            cmd!(sh, "forge build lib/solady/test/utils/mocks/MockERC20.sol").run()?;
            cmd!(sh, "forge build lib/solady/test/utils/mocks/MockERC721.sol").run()?;

            // Drop the dir guard to return to original directory
            drop(_dir);

            // Change to the tests/e2e/layerzero/contracts directory to build contracts
            let layerzero_dir = "tests/e2e/layerzero/contracts";
            let _dir = sh.push_dir(layerzero_dir);
            cmd!(sh, "./build.sh").run()?;

            // Drop the dir guard to return to original directory
            drop(_dir);

            // Get the absolute path for TEST_CONTRACTS
            let current_dir = env::current_dir()?;
            let contracts_path = current_dir.join("tests/account/out");
            let layerzero_path = current_dir.join("tests/e2e/layerzero/contracts/out");

            println!("Running e2e tests...");

            // Run the e2e tests with TEST_CONTRACTS environment variable
            let mut cmd = cmd!(sh, "cargo nextest run")
                .env("TEST_CONTRACTS", contracts_path)
                .env("LAYERZERO_CONTRACTS", layerzero_path);

            if !rest.is_empty() {
                cmd = cmd.args(rest);
            }

            cmd.run()?;
        }
    }

    Ok(())
}
