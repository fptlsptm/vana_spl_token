use clap::{
    crate_description, crate_name, crate_version, value_t, value_t_or_exit, App, AppSettings, Arg,
    ArgMatches, SubCommand,
};
use serde::Serialize;
use solana_account_decoder::{
    parse_token::{TokenAccountType, UiAccountState},
    UiAccountData,
};
use solana_clap_utils::{
    fee_payer::fee_payer_arg,
    input_parsers::{pubkey_of, pubkey_of_signer, pubkeys_of_multiple_signers, value_of},
    input_validators::{
        is_amount, is_amount_or_all, is_parsable, is_url_or_moniker, is_valid_pubkey,
        is_valid_signer, normalize_to_url_if_moniker,
    },
    keypair::{signer_from_path, CliSignerInfo},
    memo::memo_arg,
    nonce::*,
    offline::{self, *},
    ArgConstant, DisplayError,
};
use solana_cli_output::{
    return_signers_data, CliSignOnlyData, CliSignature, OutputFormat, QuietDisplay,
    ReturnSignersConfig, VerboseDisplay,
};
use solana_client::{
    blockhash_query::BlockhashQuery, rpc_client::RpcClient, rpc_request::TokenAccountsFilter,
};
use solana_remote_wallet::remote_wallet::RemoteWalletManager;

use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account,
};
use spl_token::{
    instruction::*,
    native_mint,
    state::{Account, Mint, Multisig},
};
use std::{
    collections::HashMap, fmt::Display, process::exit, str::FromStr, string::ToString, sync::Arc,
};
use strum_macros::{EnumString, IntoStaticStr, ToString};

pub const OWNER_ADDRESS_ARG: ArgConstant<'static> = ArgConstant {
    name: "owner",
    long: "owner",
    help: "Address of the token's owner. Defaults to the client keypair address.",
};

pub const OWNER_KEYPAIR_ARG: ArgConstant<'static> = ArgConstant {
    name: "owner",
    long: "owner",
    help: "Keypair of the token's owner. Defaults to the client keypair.",
};

pub const MINT_ADDRESS_ARG: ArgConstant<'static> = ArgConstant {
    name: "mint_address",
    long: "mint-address",
    help: "Address of mint that token account is associated with. Required by --sign-only",
};

pub const MINT_DECIMALS_ARG: ArgConstant<'static> = ArgConstant {
    name: "mint_decimals",
    long: "mint-decimals",
    help: "Decimals of mint that token account is associated with. Required by --sign-only",
};


pub const MULTISIG_SIGNER_ARG: ArgConstant<'static> = ArgConstant {
    name: "multisig_signer",
    long: "multisig-signer",
    help: "Member signer of a multisig account",
};

#[derive(Debug, Clone, Copy, PartialEq, EnumString, IntoStaticStr, ToString)]
#[strum(serialize_all = "kebab-case")]
pub enum CommandName {CreateToken,Close,Bench,CreateAccount,CreateMultisig,Authorize,Transfer,Burn,Mint,Freeze,Thaw,Wrap,Unwrap,Approve,Revoke,Balance,Supply,Accounts,Address,AccountInfo,MultisigInfo,Gc,SyncNative,}
pub fn owner_address_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name(OWNER_ADDRESS_ARG.name)
        .long(OWNER_ADDRESS_ARG.long)
        .takes_value(true)
        .value_name("OWNER_ADDRESS")
        .validator(is_valid_pubkey)
        .help(OWNER_ADDRESS_ARG.help)
}
pub fn owner_keypair_arg_with_value_name<'a, 'b>(value_name: &'static str) -> Arg<'a, 'b> {
    Arg::with_name(OWNER_KEYPAIR_ARG.name)
        .long(OWNER_KEYPAIR_ARG.long)
        .takes_value(true)
        .value_name(value_name)
        .validator(is_valid_signer)
        .help(OWNER_KEYPAIR_ARG.help)
}
pub fn owner_keypair_arg<'a, 'b>() -> Arg<'a, 'b> {
    owner_keypair_arg_with_value_name("OWNER_KEYPAIR")
}
pub fn mint_address_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name(MINT_ADDRESS_ARG.name)
        .long(MINT_ADDRESS_ARG.long)
        .takes_value(true)
        .value_name("MINT_ADDRESS")
        .validator(is_valid_pubkey)
        .requires(SIGN_ONLY_ARG.name)
        .requires(BLOCKHASH_ARG.name)
        .help(MINT_ADDRESS_ARG.help)
}
fn is_mint_decimals(string: String) -> Result<(), String> {
    is_parsable::<u8>(string)
}
pub fn mint_decimals_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name(MINT_DECIMALS_ARG.name)
        .long(MINT_DECIMALS_ARG.long)
        .takes_value(true)
        .value_name("MINT_DECIMALS")
        .validator(is_mint_decimals)
        .requires(SIGN_ONLY_ARG.name)
        .requires(BLOCKHASH_ARG.name)
        .help(MINT_DECIMALS_ARG.help)
}
pub trait MintArgs {
    fn mint_args(self) -> Self;
}
impl MintArgs for App<'_, '_> {
    fn mint_args(self) -> Self {
        self.arg(mint_address_arg().requires(MINT_DECIMALS_ARG.name))
            .arg(mint_decimals_arg().requires(MINT_ADDRESS_ARG.name))
    }
}
pub(crate) type Error = Box<dyn std::error::Error>;

type BulkSigners = Vec<Box<dyn Signer>>;
pub(crate) type CommandResult = Result<String, Error>;

fn new_throwaway_signer() -> (Box<dyn Signer>, Pubkey) {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();
    (Box::new(keypair) as Box<dyn Signer>, pubkey)
}

pub(crate) fn check_fee_payer_balance(config: &Config, required_balance: u64) -> Result<(), Error> {
    let balance = config.rpc_client.get_balance(&config.fee_payer)?;
    if balance < required_balance {
        Err(format!(
            "Fee payer, {}, has insufficient balance: {} required, {} available",
            config.fee_payer,
            lamports_to_sol(required_balance),
            lamports_to_sol(balance)
        )
        .into())
    } else {
        Ok(())
    }
}
type SignersOf = Vec<(Box<dyn Signer>, Pubkey)>;

#[allow(clippy::too_many_arguments)]
fn command_create_token(
    config: &Config,
    decimals: u8,
    token: Pubkey,
    authority: Pubkey,
    enable_freeze: bool,
    memo: Option<String>,
    bulk_signers: Vec<Box<dyn Signer>>,
) -> CommandResult {
    println_display(config, format!("Creating token {}", token));

    let minimum_balance_for_rent_exemption = if !config.sign_only {
        config
            .rpc_client
            .get_minimum_balance_for_rent_exemption(Mint::LEN)?
    } else {
        0
    };
    let freeze_authority_pubkey = if enable_freeze { Some(authority) } else { None };

    let mut instructions = vec![
        system_instruction::create_account(
            &config.fee_payer,
            &token,
            minimum_balance_for_rent_exemption,
            Mint::LEN as u64,
            &config.program_id,
        ),
        initialize_mint(
            &config.program_id,
            &token,
            &authority,
            freeze_authority_pubkey.as_ref(),
            decimals,
        )?,
    ];
    if let Some(text) = memo {
        instructions.push(spl_memo::build_memo(text.as_bytes(), &[&config.fee_payer]));
    }

    let tx_return = handle_tx(
        &CliSignerInfo {
            signers: bulk_signers,
        },
        config,
        false,
        minimum_balance_for_rent_exemption,
        instructions,
    )?;

    Ok(match tx_return {
        TransactionReturnData::CliSignature(cli_signature) => format_output(
            CliMint {
                address: token.to_string(),
                decimals,
                transaction_data: cli_signature,
            },
            &CommandName::CreateToken,
            config,
        ),
        TransactionReturnData::CliSignOnlyData(cli_sign_only_data) => {
            format_output(cli_sign_only_data, &CommandName::CreateToken, config)
        }
    })
}

fn command_create_account(
    config: &Config,
    token: Pubkey,
    owner: Pubkey,
    maybe_account: Option<Pubkey>,
    bulk_signers: Vec<Box<dyn Signer>>,
) -> CommandResult {
    let minimum_balance_for_rent_exemption = if !config.sign_only {
        config
            .rpc_client
            .get_minimum_balance_for_rent_exemption(Account::LEN)?
    } else {
        0
    };

    let (account, system_account_ok, instructions) = if let Some(account) = maybe_account {
        println_display(config, format!("Creating account {}", account));
        (
            account,
            false,
            vec![
                system_instruction::create_account(
                    &config.fee_payer,
                    &account,
                    minimum_balance_for_rent_exemption,
                    Account::LEN as u64,
                    &config.program_id,
                ),
                initialize_account(&config.program_id, &account, &token, &owner)?,
            ],
        )
    } else {
        let account = get_associated_token_address(&owner, &token);
        println_display(config, format!("Creating account {}", account));
        (
            account,
            true,
            vec![create_associated_token_account(
                &config.fee_payer,
                &owner,
                &token,
            )],
        )
    };

    if !config.sign_only {
        if let Some(account_data) = config
            .rpc_client
            .get_account_with_commitment(&account, config.rpc_client.commitment())?
            .value
        {
            if !(account_data.owner == system_program::id() && system_account_ok) {
                return Err(format!("Error: Account already exists: {}", account).into());
            }
        }
    }

    let tx_return = handle_tx(
        &CliSignerInfo {
            signers: bulk_signers,
        },
        config,
        false,
        minimum_balance_for_rent_exemption,
        instructions,
    )?;

    Ok(match tx_return {
        TransactionReturnData::CliSignature(signature) => {
            config.output_format.formatted_string(&signature)
        }
        TransactionReturnData::CliSignOnlyData(sign_only_data) => {
            config.output_format.formatted_string(&sign_only_data)
        }
    })
}



#[allow(clippy::too_many_arguments)]
fn command_authorize(
    config: &Config,
    account: Pubkey,
    authority_type: AuthorityType,
    authority: Pubkey,
    new_authority: Option<Pubkey>,
    force_authorize: bool,
    bulk_signers: BulkSigners,
) -> CommandResult {
    let auth_str = match authority_type {
        AuthorityType::MintTokens => "mint authority",
        AuthorityType::FreezeAccount => "freeze authority",
        AuthorityType::AccountOwner => "owner",
        AuthorityType::CloseAccount => "close authority",
    };
    let previous_authority = if !config.sign_only {
        let target_account = config.rpc_client.get_account(&account)?;
        if let Ok(mint) = Mint::unpack(&target_account.data) {
            match authority_type {
                AuthorityType::AccountOwner | AuthorityType::CloseAccount => Err(format!(
                    "Authority type `{}` not supported for SPL Token mints",
                    auth_str
                )),
                AuthorityType::MintTokens => Ok(mint.mint_authority),
                AuthorityType::FreezeAccount => Ok(mint.freeze_authority),
            }
        } else if let Ok(token_account) = Account::unpack(&target_account.data) {
            let check_associated_token_account = || -> Result<(), Error> {
                let maybe_associated_token_account =
                    get_associated_token_address(&token_account.owner, &token_account.mint);
                if account == maybe_associated_token_account
                    && !force_authorize
                    && Some(authority) != new_authority
                {
                    Err(format!(
                        "Error: attempting to change the `{}` of an associated token account",
                        auth_str
                    )
                    .into())
                } else {
                    Ok(())
                }
            };

            match authority_type {
                AuthorityType::MintTokens | AuthorityType::FreezeAccount => Err(format!(
                    "Authority type `{}` not supported for SPL Token accounts",
                    auth_str
                )),
                AuthorityType::AccountOwner => {
                    check_associated_token_account()?;
                    Ok(COption::Some(token_account.owner))
                }
                AuthorityType::CloseAccount => {
                    check_associated_token_account()?;
                    Ok(COption::Some(
                        token_account.close_authority.unwrap_or(token_account.owner),
                    ))
                }
            }
        } else {
            Err("Unsupported account data format".to_string())
        }?
    } else {
        COption::None
    };
    println_display(
        config,
        format!(
            "Updating {}\n  Current {}: {}\n  New {}: {}",
            account,
            auth_str,
            previous_authority
                .map(|pubkey| pubkey.to_string())
                .unwrap_or_else(|| "disabled".to_string()),
            auth_str,
            new_authority
                .map(|pubkey| pubkey.to_string())
                .unwrap_or_else(|| "disabled".to_string())
        ),
    );

    let instructions = vec![set_authority(
        &config.program_id,
        &account,
        new_authority.as_ref(),
        authority_type,
        &authority,
        &config.multisigner_pubkeys,
    )?];
    let tx_return = handle_tx(
        &CliSignerInfo {
            signers: bulk_signers,
        },
        config,
        false,
        0,
        instructions,
    )?;
    Ok(match tx_return {
        TransactionReturnData::CliSignature(signature) => {
            config.output_format.formatted_string(&signature)
        }
        TransactionReturnData::CliSignOnlyData(sign_only_data) => {
            config.output_format.formatted_string(&sign_only_data)
        }
    })
}



fn validate_mint(config: &Config, token: Pubkey) -> Result<(), Error> {
    let mint = config.rpc_client.get_account(&token);
    if mint.is_err() || Mint::unpack(&mint.unwrap().data).is_err() {
        return Err(format!("Invalid mint account {:?}", token).into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn command_transfer(
    config: &Config,
    token: Pubkey,
    ui_amount: Option<f64>,
    recipient: Pubkey,
    sender: Option<Pubkey>,
    sender_owner: Pubkey,
    allow_unfunded_recipient: bool,
    fund_recipient: bool,
    mint_decimals: Option<u8>,
    recipient_is_ata_owner: bool,
    use_unchecked_instruction: bool,
    memo: Option<String>,
    bulk_signers: BulkSigners,
    no_wait: bool,
    allow_non_system_account_recipient: bool,
) -> CommandResult {
    let sender = if let Some(sender) = sender {
        sender
    } else {
        get_associated_token_address(&sender_owner, &token)
    };
    let (mint_pubkey, decimals) = resolve_mint_info(config, &sender, Some(token), mint_decimals)?;
    let maybe_transfer_balance =
        ui_amount.map(|ui_amount| spl_token::ui_amount_to_amount(ui_amount, decimals));
    let transfer_balance = if !config.sign_only {
        let sender_token_amount = config
            .rpc_client
            .get_token_account_balance(&sender)
            .map_err(|err| {
                format!(
                    "Error: Failed to get token balance of sender address {}: {}",
                    sender, err
                )
            })?;
        let sender_balance = sender_token_amount.amount.parse::<u64>().map_err(|err| {
            format!(
                "Token account {} balance could not be parsed: {}",
                sender, err
            )
        })?;

        let transfer_balance = maybe_transfer_balance.unwrap_or(sender_balance);
        println_display(
            config,
            format!(
                "Transfer {} tokens\n  Sender: {}\n  Recipient: {}",
                spl_token::amount_to_ui_amount(transfer_balance, decimals),
                sender,
                recipient
            ),
        );

        if transfer_balance > sender_balance {
            return Err(format!(
                "Error: Sender has insufficient funds, current balance is {}",
                sender_token_amount.real_number_string_trimmed()
            )
            .into());
        }
        transfer_balance
    } else {
        maybe_transfer_balance.unwrap()
    };

    let mut instructions = vec![];

    let mut recipient_token_account = recipient;
    let mut minimum_balance_for_rent_exemption = 0;

    let recipient_is_token_account = if !config.sign_only {
        let recipient_account_info = config
            .rpc_client
            .get_account_with_commitment(&recipient, config.rpc_client.commitment())?
            .value
            .map(|account| {
                (
                    account.owner == config.program_id && account.data.len() == Account::LEN,
                    account.owner == system_program::id(),
                )
            });
        if let Some((recipient_is_token_account, recipient_is_system_account)) =
            recipient_account_info
        {
            if !recipient_is_token_account
                && !recipient_is_system_account
                && !allow_non_system_account_recipient
            {
                return Err("Error: The recipient address is not owned by the System Program. \
                                     Add `--allow-non-system-account-recipient` to complete the transfer. \
                                    ".into());
            }
        } else if recipient_account_info.is_none() && !allow_unfunded_recipient {
            return Err("Error: The recipient address is not funded. \
                                    Add `--allow-unfunded-recipient` to complete the transfer. \
                                   "
            .into());
        }
        recipient_account_info
            .map(|(recipient_is_token_account, _)| recipient_is_token_account)
            .unwrap_or(false)
    } else {
        !recipient_is_ata_owner
    };

    if !recipient_is_token_account {
        recipient_token_account = get_associated_token_address(&recipient, &mint_pubkey);
        println_display(
            config,
            format!(
                "  Recipient associated token account: {}",
                recipient_token_account
            ),
        );

        let needs_funding = if !config.sign_only {
            if let Some(recipient_token_account_data) = config
                .rpc_client
                .get_account_with_commitment(
                    &recipient_token_account,
                    config.rpc_client.commitment(),
                )?
                .value
            {
                if recipient_token_account_data.owner == system_program::id() {
                    true
                } else if recipient_token_account_data.owner == config.program_id {
                    false
                } else {
                    return Err(
                        format!("Error: Unsupported recipient address: {}", recipient).into(),
                    );
                }
            } else {
                true
            }
        } else {
            fund_recipient
        };

        if needs_funding {
            if fund_recipient {
                if !config.sign_only {
                    minimum_balance_for_rent_exemption += config
                        .rpc_client
                        .get_minimum_balance_for_rent_exemption(Account::LEN)?;
                    println_display(
                        config,
                        format!(
                            "  Funding recipient: {} ({} SOL)",
                            recipient_token_account,
                            lamports_to_sol(minimum_balance_for_rent_exemption)
                        ),
                    );
                }
                instructions.push(create_associated_token_account(
                    &config.fee_payer,
                    &recipient,
                    &mint_pubkey,
                ));
            } else {
                return Err(
                    "Error: Recipient's associated token account does not exist. \
                                    Add `--fund-recipient` to fund their account"
                        .into(),
                );
            }
        }
    }

    if use_unchecked_instruction {
        instructions.push(transfer(
            &config.program_id,
            &sender,
            &recipient_token_account,
            &sender_owner,
            &config.multisigner_pubkeys,
            transfer_balance,
        )?);
    } else {
        instructions.push(transfer_checked(
            &config.program_id,
            &sender,
            &mint_pubkey,
            &recipient_token_account,
            &sender_owner,
            &config.multisigner_pubkeys,
            transfer_balance,
            decimals,
        )?);
    }
    if let Some(text) = memo {
        instructions.push(spl_memo::build_memo(text.as_bytes(), &[&config.fee_payer]));
    }
    let tx_return = handle_tx(
        &CliSignerInfo {
            signers: bulk_signers,
        },
        config,
        no_wait,
        minimum_balance_for_rent_exemption,
        instructions,
    )?;
    Ok(match tx_return {
        TransactionReturnData::CliSignature(signature) => {
            config.output_format.formatted_string(&signature)
        }
        TransactionReturnData::CliSignOnlyData(sign_only_data) => {
            config.output_format.formatted_string(&sign_only_data)
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn command_burn(
    config: &Config,
    source: Pubkey,
    source_owner: Pubkey,
    ui_amount: f64,
    mint_address: Option<Pubkey>,
    mint_decimals: Option<u8>,
    use_unchecked_instruction: bool,
    memo: Option<String>,
    bulk_signers: BulkSigners,
) -> CommandResult {
    println_display(
        config,
        format!("Burn {} tokens\n  Source: {}", ui_amount, source),
    );

    let (mint_pubkey, decimals) = resolve_mint_info(config, &source, mint_address, mint_decimals)?;
    let amount = spl_token::ui_amount_to_amount(ui_amount, decimals);

    let mut instructions = if use_unchecked_instruction {
        vec![burn(
            &config.program_id,
            &source,
            &mint_pubkey,
            &source_owner,
            &config.multisigner_pubkeys,
            amount,
        )?]
    } else {
        vec![burn_checked(
            &config.program_id,
            &source,
            &mint_pubkey,
            &source_owner,
            &config.multisigner_pubkeys,
            amount,
            decimals,
        )?]
    };
    if let Some(text) = memo {
        instructions.push(spl_memo::build_memo(text.as_bytes(), &[&config.fee_payer]));
    }
    let tx_return = handle_tx(
        &CliSignerInfo {
            signers: bulk_signers,
        },
        config,
        false,
        0,
        instructions,
    )?;
    Ok(match tx_return {
        TransactionReturnData::CliSignature(signature) => {
            config.output_format.formatted_string(&signature)
        }
        TransactionReturnData::CliSignOnlyData(sign_only_data) => {
            config.output_format.formatted_string(&sign_only_data)
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn command_mint(
    config: &Config,
    token: Pubkey,
    ui_amount: f64,
    recipient: Pubkey,
    mint_decimals: Option<u8>,
    mint_authority: Pubkey,
    use_unchecked_instruction: bool,
    bulk_signers: BulkSigners,
) -> CommandResult {
    println_display(
        config,
        format!(
            "Minting {} tokens\n  Token: {}\n  Recipient: {}",
            ui_amount, token, recipient
        ),
    );

    let (_, decimals) = resolve_mint_info(config, &recipient, None, mint_decimals)?;
    let amount = spl_token::ui_amount_to_amount(ui_amount, decimals);

    let instructions = if use_unchecked_instruction {
        vec![mint_to(
            &config.program_id,
            &token,
            &recipient,
            &mint_authority,
            &config.multisigner_pubkeys,
            amount,
        )?]
    } else {
        vec![mint_to_checked(
            &config.program_id,
            &token,
            &recipient,
            &mint_authority,
            &config.multisigner_pubkeys,
            amount,
            decimals,
        )?]
    };
    let tx_return = handle_tx(
        &CliSignerInfo {
            signers: bulk_signers,
        },
        config,
        false,
        0,
        instructions,
    )?;
    Ok(match tx_return {
        TransactionReturnData::CliSignature(signature) => {
            config.output_format.formatted_string(&signature)
        }
        TransactionReturnData::CliSignOnlyData(sign_only_data) => {
            config.output_format.formatted_string(&sign_only_data)
        }
    })
}
fn command_revoke(
    config: &Config,
    account: Pubkey,
    owner: Pubkey,
    delegate: Option<Pubkey>,
    bulk_signers: BulkSigners,
) -> CommandResult {
    let delegate = if !config.sign_only {
        let source_account = config
            .rpc_client
            .get_token_account(&account)?
            .ok_or_else(|| format!("Could not find token account {}", account))?;

        if let Some(string) = source_account.delegate {
            Some(Pubkey::from_str(&string)?)
        } else {
            None
        }
    } else {
        delegate
    };

    if let Some(delegate) = delegate {
        println_display(
            config,
            format!(
                "Revoking approval\n  Account: {}\n  Delegate: {}",
                account, delegate
            ),
        );
    } else {
        return Err(format!("No delegate on account {}", account).into());
    }

    let instructions = vec![revoke(
        &config.program_id,
        &account,
        &owner,
        &config.multisigner_pubkeys,
    )?];
    let tx_return = handle_tx(
        &CliSignerInfo {
            signers: bulk_signers,
        },
        config,
        false,
        0,
        instructions,
    )?;
    Ok(match tx_return {
        TransactionReturnData::CliSignature(signature) => {
            config.output_format.formatted_string(&signature)
        }
        TransactionReturnData::CliSignOnlyData(sign_only_data) => {
            config.output_format.formatted_string(&sign_only_data)
        }
    })
}
fn command_balance(config: &Config, address: Pubkey) -> CommandResult {
    let balance = config
        .rpc_client
        .get_token_account_balance(&address)
        .map_err(|_| format!("Could not find token account {}", address))?;
    let cli_token_amount = CliTokenAmount { amount: balance };
    Ok(config.output_format.formatted_string(&cli_token_amount))
}
fn command_supply(config: &Config, address: Pubkey) -> CommandResult {
    let supply = config.rpc_client.get_token_supply(&address)?;
    let cli_token_amount = CliTokenAmount { amount: supply };
    Ok(config.output_format.formatted_string(&cli_token_amount))
}
fn command_accounts(config: &Config, token: Option<Pubkey>, owner: Pubkey) -> CommandResult {
    if let Some(token) = token {
        validate_mint(config, token)?;
    }
    let accounts = config.rpc_client.get_token_accounts_by_owner(
        &owner,
        match token {
            Some(token) => TokenAccountsFilter::Mint(token),
            None => TokenAccountsFilter::ProgramId(config.program_id),
        },
    )?;
    if accounts.is_empty() {
        println!("None");
        return Ok("".to_string());
    }

    let (mint_accounts, unsupported_accounts, max_len_balance, includes_aux) =
        sort_and_parse_token_accounts(&owner, accounts, &config.program_id);
    let aux_len = if includes_aux { 10 } else { 0 };

    let cli_token_accounts = CliTokenAccounts {
        accounts: mint_accounts
            .into_iter()
            .map(|(_mint, accounts_list)| accounts_list)
            .collect(),
        unsupported_accounts,
        max_len_balance,
        aux_len,
        token_is_some: token.is_some(),
    };
    Ok(config.output_format.formatted_string(&cli_token_accounts))
}
fn command_address(config: &Config, token: Option<Pubkey>, owner: Pubkey) -> CommandResult {
    let mut cli_address = CliWalletAddress {
        wallet_address: owner.to_string(),
        ..CliWalletAddress::default()
    };
    if let Some(token) = token {
        validate_mint(config, token)?;
        let associated_token_address = get_associated_token_address(&owner, &token);
        cli_address.associated_token_address = Some(associated_token_address.to_string());
    }
    Ok(config.output_format.formatted_string(&cli_address))
}
fn command_account_info(config: &Config, address: Pubkey) -> CommandResult {
    let account = config
        .rpc_client
        .get_token_account(&address)
        .map_err(|_| format!("Could not find token account {}", address))?
        .unwrap();
    let mint = Pubkey::from_str(&account.mint).unwrap();
    let owner = Pubkey::from_str(&account.owner).unwrap();
    let is_associated = get_associated_token_address(&owner, &mint) == address;
    let cli_token_account = CliTokenAccount {
        address: address.to_string(),
        is_associated,
        account,
    };
    Ok(config.output_format.formatted_string(&cli_token_account))
}
fn get_multisig(config: &Config, address: &Pubkey) -> Result<Multisig, Error> {
    let account = config.rpc_client.get_account(address)?;
    Multisig::unpack(&account.data).map_err(|e| e.into())
}
fn command_multisig(config: &Config, address: Pubkey) -> CommandResult {
    let multisig = get_multisig(config, &address)?;
    let n = multisig.n as usize;
    assert!(n <= multisig.signers.len());
    let cli_multisig = CliMultisig {
        address: address.to_string(),
        m: multisig.m,
        n: multisig.n,
        signers: multisig
            .signers
            .iter()
            .enumerate()
            .filter_map(|(i, signer)| {
                if i < n {
                    Some(signer.to_string())
                } else {
                    None
                }
            })
            .collect(),
    };
    Ok(config.output_format.formatted_string(&cli_multisig))
}
fn minimum_signers_help_string() -> String {
    format!(
        "The minimum number of signers required to allow the operation. [{} <= M <= N]",
        MIN_SIGNERS
    )
}
fn multisig_member_help_string() -> String {
    format!(
        "The public keys for each of the N signing members of this account. [{} <= N <= {}]",
        MIN_SIGNERS, MAX_SIGNERS
    )
}
fn main() -> Result<(), Error> {
    let default_decimals = format!("{}", native_mint::DECIMALS);
    let default_program_id = spl_token::id().to_string();
    let minimum_signers_help = minimum_signers_help_string();
    let multisig_member_help = multisig_member_help_string();
    let app_matches = app(
        &default_decimals,
        &default_program_id,
        &minimum_signers_help,
        &multisig_member_help,
    )
    .get_matches();
    let mut wallet_manager = None;
    let mut bulk_signers: Vec<Box<dyn Signer>> = Vec::new();
    let mut multisigner_ids = Vec::new();
    let (sub_command, sub_matches) = app_matches.subcommand();
    let sub_command = CommandName::from_str(sub_command).unwrap();
    let matches = sub_matches.unwrap();
    let config = {
        let cli_config = if let Some(config_file) = matches.value_of("config_file") {
            solana_cli_config::Config::load(config_file).unwrap_or_else(|_| {
                eprintln!("error: Could not find config file `{}`", config_file);
                exit(1);
            })
        } else if let Some(ref config_file) = *solana_cli_config::CONFIG_FILE {
            solana_cli_config::Config::load(config_file).unwrap_or_default()
        } else {
            solana_cli_config::Config::default()
        };
        let json_rpc_url = normalize_to_url_if_moniker(
            matches
                .value_of("json_rpc_url")
                .unwrap_or(&cli_config.json_rpc_url),
        );
        let websocket_url = solana_cli_config::Config::compute_websocket_url(&json_rpc_url);

        let (signer, fee_payer) = signer_from_path(
            matches,
            matches
                .value_of("fee_payer")
                .unwrap_or(&cli_config.keypair_path),
            "fee_payer",
            &mut wallet_manager,
        )
        .map(|s| {
            let p = s.pubkey();
            (s, p)
        })
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            exit(1);
        });
        bulk_signers.push(signer);

        let verbose = matches.is_present("verbose");
        let output_format = matches
            .value_of("output_format")
            .map(|value| match value {
                "json" => OutputFormat::Json,
                "json-compact" => OutputFormat::JsonCompact,
                _ => unreachable!(),
            })
            .unwrap_or(if verbose {
                OutputFormat::DisplayVerbose
            } else {
                OutputFormat::Display
            });

        let nonce_account = pubkey_of_signer(matches, NONCE_ARG.name, &mut wallet_manager)
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                exit(1);
            });
        let nonce_authority = if nonce_account.is_some() {
            let (signer, nonce_authority) = signer_from_path(
                matches,
                matches
                    .value_of(NONCE_AUTHORITY_ARG.name)
                    .unwrap_or(&cli_config.keypair_path),
                NONCE_AUTHORITY_ARG.name,
                &mut wallet_manager,
            )
            .map(|s| {
                let p = s.pubkey();
                (s, p)
            })
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                exit(1);
            });
            bulk_signers.push(signer);

            Some(nonce_authority)
        } else {
            None
        };
        let blockhash_query = BlockhashQuery::new_from_matches(matches);
        let sign_only = matches.is_present(SIGN_ONLY_ARG.name);
        let dump_transaction_message = matches.is_present(DUMP_TRANSACTION_MESSAGE.name);
        let program_id = pubkey_of(matches, "program_id").unwrap();

        let multisig_signers = signers_of(matches, MULTISIG_SIGNER_ARG.name, &mut wallet_manager)
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                exit(1);
            });
        if let Some(mut multisig_signers) = multisig_signers {
            multisig_signers.sort_by(|(_, lp), (_, rp)| lp.cmp(rp));
            let (signers, pubkeys): (Vec<_>, Vec<_>) = multisig_signers.into_iter().unzip();
            bulk_signers.extend(signers);
            multisigner_ids = pubkeys;
        }
        let multisigner_pubkeys = multisigner_ids.iter().collect::<Vec<_>>();

        Config {
            rpc_client: Arc::new(RpcClient::new_with_commitment(json_rpc_url,CommitmentConfig::confirmed(),)),
            websocket_url,output_format,fee_payer,default_keypair: KeypairOrPath::Path(cli_config.keypair_path),nonce_account,nonce_authority,blockhash_query,sign_only,dump_transaction_message,multisigner_pubkeys,program_id,
        }
    };
    solana_logger::setup_with_default("solana=info");
    let result = process_command(&sub_command, matches, &config, wallet_manager, bulk_signers)
        .map_err::<Error, _>(|err| DisplayError::new_as_boxed(err).into())?;
    println!("{}", result);
    Ok(())
}
fn format_output<T>(command_output: T, command_name: &CommandName, config: &Config) -> String where T: Serialize + Display + QuietDisplay + VerboseDisplay,
{
    config.output_format.formatted_string(&CommandOutput {
        command_name: command_name.to_string(),
        command_output,
    })
}
enum TransactionReturnData {
    CliSignature(CliSignature),
    CliSignOnlyData(CliSignOnlyData),
}
fn handle_tx(
    signer_info: &CliSignerInfo,
    config: &Config,
    no_wait: bool,
    minimum_balance_for_rent_exemption: u64,
    instructions: Vec<Instruction>,
) -> Result<TransactionReturnData, Box<dyn std::error::Error>> {
    let fee_payer = Some(&config.fee_payer);
    let message = if let Some(nonce_account) = config.nonce_account.as_ref() {
        Message::new_with_nonce(
            instructions,
            fee_payer,
            nonce_account,
            config.nonce_authority.as_ref().unwrap(),
        )
    } else {
        Message::new(&instructions, fee_payer)
    };
    let (recent_blockhash, fee_calculator) = config
        .blockhash_query
        .get_blockhash_and_fee_calculator(&config.rpc_client, config.rpc_client.commitment())
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            exit(1);
        });

    if !config.sign_only {
        check_fee_payer_balance(config,minimum_balance_for_rent_exemption + fee_calculator.calculate_fee(&message),)?;
    }
    let signers = signer_info.signers_for_message(&message);
    let mut transaction = Transaction::new_unsigned(message);

    if config.sign_only {
        transaction.try_partial_sign(&signers, recent_blockhash)?;
        Ok(TransactionReturnData::CliSignOnlyData(return_signers_data(
            &transaction,
            &ReturnSignersConfig {
                dump_transaction_message: config.dump_transaction_message,
            },
        )))
    } else {
        transaction.try_sign(&signers, recent_blockhash)?;
        let signature = if no_wait {
            config.rpc_client.send_transaction(&transaction)?
        } else {
            config.rpc_client.send_and_confirm_transaction_with_spinner(&transaction)?
        };
        Ok(TransactionReturnData::CliSignature(CliSignature {
            signature: signature.to_string(),
        }))
    }
}
