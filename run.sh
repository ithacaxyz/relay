# Run 5 instances concurrently
for i in {1..5}; do
    TEST_FORK_URL=https://base-sepolia.rpc.ithaca.xyz \
    TEST_ORCHESTRATOR=0x8a222a12a8613ea934c33e15f280e7a83082433b \
    TEST_PROXY=0xa600fdc16765616106cf6c7d7b2bfe8d540bc3f2 \
    TEST_SIMULATOR=0x7d89b79fb112989e5bccda333b7fb64df3825ee6 \
    TEST_FORK_BLOCK_NUMBER_PINNED=27911720 \
    cargo nextest run test_basic_concurrent --nocapture &
done
wait # Wait for all background jobs to complete