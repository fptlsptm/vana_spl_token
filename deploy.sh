# vana coin spl-token cil distribution source
set -e

solana config get

# Mainnet settings
solana config set --https://solana-api.projectserum.com
solana config set --keypair ${HOME}/devnet.json

# Token Mint
spl-token accounts
spl-token create-account 2VgswiQzjXyJC4Vqm8pQy6Wc9AbC9bC2pHwqQ4mHcqbx
spl-token mint 2VgswiQzjXyJC4Vqm8pQy6Wc9AbC9bC2pHwqQ4mHcqbx 1000000000
spl-token authorize 2VgswiQzjXyJC4Vqm8pQy6Wc9AbC9bC2pHwqQ4mHcqbx mint --disable --url mainnet-beta
