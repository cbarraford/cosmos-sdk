// nolint
package auth

import (
	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	dbm "github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/libs/log"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/params/subspace"
)

type testInput struct {
	cdc *codec.Codec
	ctx sdk.Context
	ak  AccountKeeper
}

func setupTestInput() testInput {
	db := dbm.NewMemDB()

	cdc := codec.New()
	RegisterBaseAccount(cdc)

	authCapKey := sdk.NewKVStoreKey("authCapKey")
	keyParams := sdk.NewKVStoreKey("subspace")
	tkeyParams := sdk.NewTransientStoreKey("transient_subspace")

	ms := store.NewCommitMultiStore(db)
	ms.MountStoreWithDB(authCapKey, sdk.StoreTypeIAVL, db)
	ms.MountStoreWithDB(keyParams, sdk.StoreTypeIAVL, db)
	ms.MountStoreWithDB(tkeyParams, sdk.StoreTypeTransient, db)
	ms.LoadLatestVersion()

	ps := subspace.NewSubspace(cdc, keyParams, tkeyParams, DefaultParamspace)
	ak := NewAccountKeeper(cdc, authCapKey, ps, ProtoBaseAccount)
	ctx := sdk.NewContext(ms, abci.Header{ChainID: "test-chain-id"}, false, log.NewNopLogger())

	ak.SetParams(ctx, DefaultParams())

	feeCollector := ak.NewAccountWithAddress(ctx, FeeCollectorAddr)
	ak.SetAccount(ctx, feeCollector)

	return testInput{cdc: cdc, ctx: ctx, ak: ak}
}

func newTestMsg(addrs ...sdk.AccAddress) *sdk.TestMsg {
	return sdk.NewTestMsg(addrs...)
}

func newStdFee() StdFee {
	return NewStdFee(50000,
		sdk.NewCoins(sdk.NewInt64Coin("atom", 150)),
	)
}

// coins to more than cover the fee
func newCoins() sdk.Coins {
	return sdk.Coins{
		sdk.NewInt64Coin("atom", 10000000),
	}
}

func keyPubAddr() (crypto.PrivKey, crypto.PubKey, sdk.AccAddress) {
	key := secp256k1.GenPrivKey()
	pub := key.PubKey()
	addr := sdk.AccAddress(pub.Address())
	return key, pub, addr
}

func newTestTx(ctx sdk.Context, msgs []sdk.Msg, privs []crypto.PrivKey, accNums []uint64, seqs []uint64, fee StdFee) sdk.Tx {
	sigs := make([]StdSignature, len(privs))
	for i, priv := range privs {
		signBytes := StdSignBytes(ctx.ChainID(), accNums[i], seqs[i], fee, msgs, "")

		sig, err := priv.Sign(signBytes)
		if err != nil {
			panic(err)
		}

		sigs[i] = StdSignature{PubKey: priv.PubKey(), Signature: sig}
	}

	tx := NewStdTx(msgs, fee, sigs, "")
	return tx
}

func newTestTxWithMemo(ctx sdk.Context, msgs []sdk.Msg, privs []crypto.PrivKey, accNums []uint64, seqs []uint64, fee StdFee, memo string) sdk.Tx {
	sigs := make([]StdSignature, len(privs))
	for i, priv := range privs {
		signBytes := StdSignBytes(ctx.ChainID(), accNums[i], seqs[i], fee, msgs, memo)

		sig, err := priv.Sign(signBytes)
		if err != nil {
			panic(err)
		}

		sigs[i] = StdSignature{PubKey: priv.PubKey(), Signature: sig}
	}

	tx := NewStdTx(msgs, fee, sigs, memo)
	return tx
}

func newTestTxWithSignBytes(msgs []sdk.Msg, privs []crypto.PrivKey, accNums []uint64, seqs []uint64, fee StdFee, signBytes []byte, memo string) sdk.Tx {
	sigs := make([]StdSignature, len(privs))
	for i, priv := range privs {
		sig, err := priv.Sign(signBytes)
		if err != nil {
			panic(err)
		}

		sigs[i] = StdSignature{PubKey: priv.PubKey(), Signature: sig}
	}

	tx := NewStdTx(msgs, fee, sigs, memo)
	return tx
}
