// See https://aka.ms/new-console-template for more information

using System.Net;
using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.RPC;
using NBitcoin.Secp256k1;
using NBitcoin.Secp256k1.Musig;

var network = Network.RegTest;


var rpc = new RPCClient(new NetworkCredential("admin1", "123"), new Uri("http://localhost:18443"));
await WitnessV1Musig2();
await WitnessV1Musig2();
await WitnessV1Musig2();
// await WitnessV1SimpleMultisig();
async Task WitnessV0SimpleMultisig()
{
    var keyA = new Key();
    var keyB = new Key();
    var keyC = new Key();
    var multisigAndCRedeem = new Script(
        Op.GetPushOp(2),
        Op.GetPushOp(keyA.PubKey.ToBytes()),
        Op.GetPushOp(keyB.PubKey.ToBytes()),
        Op.GetPushOp(2),
        OpcodeType.OP_CHECKMULTISIGVERIFY,
        Op.GetPushOp(keyC.PubKey.ToBytes()),
        OpcodeType.OP_CHECKSIG);
    var p2swshScript = multisigAndCRedeem.WitHash.ScriptPubKey;
    var p2wshAddress = p2swshScript.GetDestinationAddress(network);
    await rpc.GenerateAsync(1);
    var coin = new ScriptCoin(
        (await rpc.GetRawTransactionAsync(await rpc.SendToAddressAsync(p2wshAddress, Money.Coins(1m)))).Outputs
        .AsCoins()
        .First(coin1 => coin1.TxOut.IsTo(p2wshAddress)), multisigAndCRedeem);

    var tx = network.CreateTransaction()!;
    tx.Outputs.Add(Money.Coins(0.9999m), p2wshAddress.ScriptPubKey);
    tx.Inputs.Add(new TxIn(coin.Outpoint));


    uint256 hashAll = tx.GetSignatureHash(multisigAndCRedeem, 0, SigHash.All, coin.TxOut, HashVersion.WitnessV0);
    uint256 hashACP_NONE = tx.GetSignatureHash(multisigAndCRedeem, 0, SigHash.AnyoneCanPay | SigHash.None, coin.TxOut,
        HashVersion.WitnessV0);

    List<Op> witnessOps =
    [
        Op.GetPushOp(keyC.Sign(hashAll, new SigningOptions() { SigHash = SigHash.All })
            .ToBytes()),
        OpcodeType.OP_0,
        Op.GetPushOp(keyA.Sign(hashACP_NONE, new SigningOptions() { SigHash = SigHash.AnyoneCanPay | SigHash.None })
            .ToBytes()),
        Op.GetPushOp(keyB.Sign(hashACP_NONE, new SigningOptions() { SigHash = SigHash.AnyoneCanPay | SigHash.None })
            .ToBytes()),
        Op.GetPushOp(multisigAndCRedeem.ToBytes())
    ];
    var witness = new WitScript(witnessOps.ToArray());

    tx.Inputs[0].WitScript = witness;
    var precomputed = tx.PrecomputeTransactionData([coin]);
    var checker = new TransactionChecker(tx, (int)0, coin.TxOut, precomputed);

    var eval = new ScriptEvaluationContext
    {
        ScriptVerify = ScriptVerify.Standard,
    };
    var res = eval.VerifyScript(tx.Inputs[0].ScriptSig, tx.Inputs[0].WitScript, p2swshScript, checker);
    var mempool = await rpc.TestMempoolAcceptAsync(tx);


    Console.WriteLine(mempool.IsAllowed);
}

async Task WitnessV1SimpleMultisig()
{
    // let's check witness v1 variant with checksigadd (not musig2)

    var keyA = ECPrivKey.Create(RandomUtils.GetBytes(32));
    var keyB = ECPrivKey.Create(RandomUtils.GetBytes(32));
    var keyC = ECPrivKey.Create(RandomUtils.GetBytes(32));

    var pubKeyA = keyA.CreateXOnlyPubKey();
    var pubKeyB = keyB.CreateXOnlyPubKey();
    var pubKeyC = keyC.CreateXOnlyPubKey();
    var kKeyA = new Key(keyA.sec.ToBytes());
    var kKeyB = new Key(keyB.sec.ToBytes());
    var kKeyC = new Key(keyC.sec.ToBytes());

    var leaf = new Script(
        Op.GetPushOp(pubKeyA.ToBytes()),
        OpcodeType.OP_CHECKSIG,
        Op.GetPushOp(pubKeyB.ToBytes()),
        OpcodeType.OP_CHECKSIGADD,
        OpcodeType.OP_2,
        OpcodeType.OP_NUMEQUALVERIFY,
        Op.GetPushOp(pubKeyC.ToBytes()),
        OpcodeType.OP_CHECKSIG
    ).ToTapScript(TapLeafVersion.C0);

//use a provably false dummy key for the internal key as we only want script spending, infinity point
    var s = Scalar.One.ToBytes();
    var internalKey = new TaprootInternalPubKey(ECPrivKey.Create(s).CreateXOnlyPubKey().ToBytes());
    var builder = new TaprootBuilder();
    builder.AddLeaf(0, leaf);
    var taprootSpendInfo = builder.Finalize(internalKey);
    var address = taprootSpendInfo.OutputPubKey.GetAddress(network);
    await rpc.GenerateAsync(1);
    var coin =
        (await rpc.GetRawTransactionAsync(await rpc.SendToAddressAsync(address, Money.Coins(1m)))).Outputs.AsCoins()
        .First(coin1 => coin1.TxOut.IsTo(address));

    var tx = network.CreateTransaction()!;
    tx.Outputs.Add(Money.Coins(0.9999m), address.ScriptPubKey);
    tx.Inputs.Add(new TxIn(coin.Outpoint));

    var precomputed = tx.PrecomputeTransactionData([coin]);
    var executionDataACP_None = new TaprootExecutionData(0, leaf.LeafHash)
        { SigHash = TaprootSigHash.AnyoneCanPay | TaprootSigHash.None };
    var executionDataAll = new TaprootExecutionData(0, leaf.LeafHash) { SigHash = TaprootSigHash.All };


    uint256 hashAll = tx.GetSignatureHashTaproot(precomputed, executionDataAll);
    uint256 hashACP_NONE = tx.GetSignatureHashTaproot(precomputed, executionDataACP_None);


    List<Op> witnessOps =
    [
        Op.GetPushOp(kKeyC.SignTaprootScriptSpend(hashAll, TaprootSigHash.All).ToBytes()),
        Op.GetPushOp(kKeyB.SignTaprootScriptSpend(hashACP_NONE, TaprootSigHash.AnyoneCanPay | TaprootSigHash.None)
            .ToBytes()),
        Op.GetPushOp(kKeyA.SignTaprootScriptSpend(hashACP_NONE, TaprootSigHash.AnyoneCanPay | TaprootSigHash.None)
            .ToBytes()),
        Op.GetPushOp(leaf.Script.ToBytes()),
        Op.GetPushOp(taprootSpendInfo.GetControlBlock(leaf).ToBytes())
    ];

    var witness = new WitScript(witnessOps.ToArray());

    tx.Inputs[0].WitScript = witness;
    var validator = tx.CreateValidator([coin.TxOut]);
    var result = validator.ValidateInput(0);

    var mempool = await rpc.TestMempoolAcceptAsync(tx);

    Console.WriteLine(mempool.IsAllowed);
}


async Task WitnessV1Musig2()
{
    // let's check witness v1 variant with musig2
    var keyA = ECPrivKey.Create(RandomUtils.GetBytes(32));
    var keyB = ECPrivKey.Create(RandomUtils.GetBytes(32));
    var keyC = ECPrivKey.Create(RandomUtils.GetBytes(32));

    var pubKeyA = keyA.CreatePubKey();
    var pubKeyB = keyB.CreatePubKey();
    
    var pubKeyC = keyC.CreateXOnlyPubKey();
    var kKeyA = new Key(keyA.sec.ToBytes());
    var kKeyB = new Key(keyB.sec.ToBytes());
    
    var kKeyC = new Key(keyC.sec.ToBytes()); 
    var aggregatedKey = ECPubKey.MusigAggregate([pubKeyA, pubKeyB]);
    

    var leaf = new Script(
        Op.GetPushOp(aggregatedKey.ToXOnlyPubKey().ToBytes()),
        OpcodeType.OP_CHECKSIG,
        Op.GetPushOp(pubKeyC.ToBytes()),
        OpcodeType.OP_CHECKSIGADD,
        OpcodeType.OP_2,
        OpcodeType.OP_NUMEQUAL
    ).ToTapScript(TapLeafVersion.C0);

    //use a provably false dummy key for the internal key as we only want script spending, infinity point
    var s = Scalar.One.ToBytes();
    var internalKey = new TaprootInternalPubKey(ECPrivKey.Create(s).CreateXOnlyPubKey().ToBytes());
    var builder = new TaprootBuilder();
    builder.AddLeaf(0, leaf);
    var taprootSpendInfo = builder.Finalize(internalKey);
    var address = taprootSpendInfo.OutputPubKey.GetAddress(network);
    await rpc.GenerateAsync(1);
    var coin =
        (await rpc.GetRawTransactionAsync(await rpc.SendToAddressAsync(address, Money.Coins(1m)))).Outputs.AsCoins()
        .First(coin1 => coin1.TxOut.IsTo(address));

    var tx = network.CreateTransaction()!;
    tx.Outputs.Add(Money.Coins(0.9999m), address.ScriptPubKey);
    tx.Inputs.Add(new TxIn(coin.Outpoint));

    var precomputed = tx.PrecomputeTransactionData([coin]);
    var executionDataACP_None = new TaprootExecutionData(0, leaf.LeafHash)
        { SigHash = TaprootSigHash.AnyoneCanPay | TaprootSigHash.None };
    var executionDataAll = new TaprootExecutionData(0, leaf.LeafHash) { SigHash = TaprootSigHash.All };


    uint256 hashAll = tx.GetSignatureHashTaproot(precomputed, executionDataAll);
    uint256 hashACP_NONE = tx.GetSignatureHashTaproot(precomputed, executionDataACP_None);

    var musig = new MusigContext([pubKeyA, pubKeyB], hashACP_NONE.ToBytes());
    
    var nonceA = musig.GenerateNonce(pubKeyA);
    var nonceB = musig.GenerateNonce(pubKeyB);
    
    musig.ProcessNonces([nonceA.CreatePubNonce(), nonceB.CreatePubNonce()]);
    
    var sigA = musig.Sign(keyA, nonceA);
    var sigB = musig.Sign(keyB, nonceB);
    var aggSignature = musig.AggregateSignatures([sigA, sigB]);
    var taprootSig = new TaprootSignature(new SchnorrSignature(aggSignature.ToBytes()),
        TaprootSigHash.AnyoneCanPay | TaprootSigHash.None);
    List<Op> witnessOps =
    [
        Op.GetPushOp(kKeyC.SignTaprootScriptSpend(hashAll, TaprootSigHash.All).ToBytes()),
        Op.GetPushOp(taprootSig.ToBytes()),
        Op.GetPushOp(leaf.Script.ToBytes()),
        Op.GetPushOp(taprootSpendInfo.GetControlBlock(leaf).ToBytes())
    ];

    var witness = new WitScript(witnessOps.ToArray());

    tx.Inputs[0].WitScript = witness;
    var validator = tx.CreateValidator([coin.TxOut]);
    var result = validator.ValidateInput(0);

    var mempool = await rpc.TestMempoolAcceptAsync(tx);

    Console.WriteLine(mempool.IsAllowed);
}