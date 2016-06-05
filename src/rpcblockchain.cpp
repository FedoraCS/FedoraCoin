// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "bitcoinrpc.h"
#include "alert.h"
#include "mixerann.h"
#include "base58.h"

using namespace json_spirit;
using namespace std;

void ScriptPubKeyToJSON(const CScript& scriptPubKey, Object& out);

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (pindexBest == NULL)
            return 1.0;
        else
            blockindex = pindexBest;
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}


Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex)
{
    Object result;
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    CMerkleTx txGen(block.vtx[0]);
    txGen.SetMerkleBranch(&block);
    result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    Array txs;
    BOOST_FOREACH(const CTransaction&tx, block.vtx)
        txs.push_back(tx.GetHash().GetHex());
    result.push_back(Pair("tx", txs));
    result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
    result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
    result.push_back(Pair("bits", HexBits(block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    if (blockindex->pnext)
        result.push_back(Pair("nextblockhash", blockindex->pnext->GetBlockHash().GetHex()));
    return result;
}

Value sendalert(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || (params.size() != 1))
            throw runtime_error(
                "sendalert <alertdata>\n"
                "Verifies the alert signature and sends to all connected peers.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    CAlert alert;
    vector<unsigned char> msgData(ParseHexV(params[0], "argument"));
    CDataStream vRecv(msgData, SER_NETWORK, PROTOCOL_VERSION);
    vRecv >> alert;
    CDataStream vRecv2(msgData, SER_NETWORK, PROTOCOL_VERSION);

    if (alert.CheckSignature())
        ProcessMessage(NULL, "alert", vRecv2);
    else
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid signature on alert, not sending");
    return true;
}

Value signalert(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || (params.size() != 2))
        throw runtime_error(
            "signalert <alertdata> <privatekey>\n"
            "Signs the alert data with the private key.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    CAlert alert;
    vector<unsigned char> msgData(ParseHexV(params[0], "argument"));
    vector<unsigned char> keyData(ParseHexV(params[1], "argument"));
    alert.vchMsg = msgData;

    CPrivKey key;
    key.reserve(keyData.size());
    copy(keyData.begin(),keyData.end(),back_inserter(key));

    CKey key2;
    key2.SetPrivKey(key, false);
    if (!key2.Sign(alert.GetHash(), alert.vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed, invalid key?");

    if (alert.CheckSignature())
    {
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << alert;

        return HexStr(ssTx.begin(), ssTx.end());
    }
    return false;
}
Value createalert(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || (params.size() < 11 || params.size() > 12))
        throw runtime_error(
            "createalert <relayuntil> <expiration> <id> <cancelupto> <ids to cancel eg [1,2]> <minprotocolver> <maxprotocolvar> <versions alert applies to eg [\"/Euphoria:1.0.6.0/\",\"/Euphoria:1.0.6.5/\"]> <priority> <comment> <statusbar> [reserved]\n"
            "Creates alert data for the given parameters.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    CUnsignedAlert alert;
    alert.SetNull();

    alert.nRelayUntil = params[0].get_int64();
    alert.nExpiration = params[1].get_int64();
    alert.nID = params[2].get_int();
    alert.nCancel = params[3].get_int();

    Array setCancels = params[4].get_array();
    BOOST_FOREACH(const Value& cid, setCancels)
    {
        alert.setCancel.insert(cid.get_int());
    }

    alert.nMinVer = params[5].get_int();
    alert.nMaxVer = params[6].get_int();
    Array setSubVer = params[7].get_array();
    BOOST_FOREACH(const Value& cid, setSubVer)
    {
        alert.setSubVer.insert(cid.get_str());
    }
    alert.nPriority = params[8].get_int();
    alert.strComment = params[9].get_str();
    alert.strStatusBar = params[10].get_str();

    if (params.size() > 11)
        alert.strReserved = params[11].get_str();

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << alert;
    return HexStr(ssTx.begin(), ssTx.end());
}

Value sendann(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || (params.size() != 1))
            throw runtime_error(
                "sendann <anndata>\n"
                "Verifies the announcement signature and sends to all connected peers.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    CAnnouncement ann;
    vector<unsigned char> msgData(ParseHexV(params[0], "argument"));
    CDataStream vRecv(msgData, SER_NETWORK, PROTOCOL_VERSION);
    vRecv >> ann;
    CDataStream vRecv2(msgData, SER_NETWORK, PROTOCOL_VERSION);

    if (ann.CheckSignature())
        ProcessMessage(NULL, "announcement", vRecv2);
    else
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid signature on announcement, not sending");
    return true;
}

Value signann(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || (params.size() != 2))
        throw runtime_error(
            "signann <alertdata> <privatekey>\n"
            "Signs the announcement data with the private key.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    CAnnouncement ann;
    vector<unsigned char> msgData(ParseHexV(params[0], "argument"));
    vector<unsigned char> keyData(ParseHexV(params[1], "argument"));
    ann.vchMsg = msgData;

    CPrivKey key;
    key.reserve(keyData.size());
    copy(keyData.begin(),keyData.end(),back_inserter(key));

    CKey key2;
    key2.SetPrivKey(key, false);
    if (!key2.Sign(ann.GetHash(), ann.vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed, invalid key?");

    if (ann.CheckSignature())
    {
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << ann;

        return HexStr(ssTx.begin(), ssTx.end());
    }
    return false;
}
Value createann(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || (params.size() != 9))
        throw runtime_error(
            "createann <expiration> <id> <ids to revoke eg [1,2]> <minprotocolver> <maxprotocolvar> <versions alert applies to eg [\"/Euphoria:1.0.6.0/\",\"/Euphoria:1.0.6.5/\"]> <hex:recvPubKey> <hex:sendPubKey> <hex:rsaPubKey>\n"
            "Creates alert data for the given parameters.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    CUnsignedAnnouncement ann;
    ann.SetNull();

    ann.nExpiration = params[0].get_int64();
    ann.nID = params[1].get_int();
    Array setRevokes = params[2].get_array();
    BOOST_FOREACH(const Value& cid, setRevokes)
    {
        ann.setRevoke.insert(cid.get_int());
    }
    ann.nMinVer = params[3].get_int();
    ann.nMaxVer = params[4].get_int();
    Array setSubVer = params[5].get_array();
    BOOST_FOREACH(const Value& cid, setSubVer)
    {
        ann.setSubVer.insert(cid.get_str());
    }

    vector<unsigned char> recv(ParseHexV(params[6], "argument"));
    vector<unsigned char> send(ParseHexV(params[7], "argument"));
    vector<unsigned char> rsa(ParseHexV(params[8], "argument"));
    ann.pReceiveAddressPubKey = recv;
    ann.pSendAddressPubKey = send;
    ann.pRsaPubKey = rsa;

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << ann;
    return HexStr(ssTx.begin(), ssTx.end());
}

Value listann(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
            "listann\n"
            "Lists active mixer announcements on this node.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    std::stringstream ss;
    ss << "Current: " << nCurrentMixer << "\r\n\r\n";
    {
        LOCK(cs_mapAnns);
        for (map<uint256, CAnnouncement>::iterator mi = mapAnns.begin(); mi != mapAnns.end(); mi++)
        {
            const CAnnouncement& ann = (*mi).second;
            ss << "========\r\n";
            ss << (*mi).first.GetHex();
            ss << "\r\n========\r\n";
            ss << ann.ToString();
            ss << "\r\n\r\n";
        }
    }
    return ss.str();
}

Value getchainvalue(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || (params.size() != 0 && params.size() != 1))
        throw runtime_error(
            "getchainvalue [height]\n"
            "Returns the total amount of coins mined on the current chain up the to given height.");

    int nHeight = nBestHeight;
    if (params.size() == 1)
        nHeight = params[0].get_int();

    return ValueFromAmount(GetChainValue(nHeight));
}
Value getblockcount(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight;
}

Value getbestblockhash(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbestblockhash\n"
            "Returns the hash of the best (tip) block in the longest block chain.");

    return hashBestChain.GetHex();
}

Value getdifficulty(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.");

    return GetDifficulty();
}


Value settxfee(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.00000001.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    // Amount
    int64 nAmount = 0;
    if (params[0].get_real() != 0.0)
        nAmount = AmountFromValue(params[0]);        // rejects 0.0 amounts

    nTransactionFee = nAmount;
    return true;
}

Value getrawmempool(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getrawmempool\n"
            "Returns all transaction ids in memory pool.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    vector<uint256> vtxid;
    mempool.queryHashes(vtxid);

    Array a;
    BOOST_FOREACH(const uint256& hash, vtxid)
        a.push_back(hash.ToString());

    return a;
}

Value getblockhash(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblockhash <index>\n"
            "Returns hash of block in best-block-chain at <index>.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > nBestHeight)
        throw runtime_error("getblockhash(): block number out of range.");

    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
    return pblockindex->phashBlock->GetHex();
}

Value getblock(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblock <hash> [verbose=true]\n"
            "If verbose is false, returns a string that is serialized, hex-encoded data for block <hash>.\n"
            "If verbose is true, returns an Object with information about block <hash>."
        );

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex);

    if (!fVerbose)
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockToJSON(block, pblockindex);
}

Value gettxoutsetinfo(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gettxoutsetinfo\n"
            "Returns statistics about the unspent transaction output set.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    Object ret;

    CCoinsStats stats;
    if (pcoinsTip->GetStats(stats)) {
        ret.push_back(Pair("height", (boost::int64_t)stats.nHeight));
        ret.push_back(Pair("bestblock", stats.hashBlock.GetHex()));
        ret.push_back(Pair("transactions", (boost::int64_t)stats.nTransactions));
        ret.push_back(Pair("txouts", (boost::int64_t)stats.nTransactionOutputs));
        ret.push_back(Pair("bytes_serialized", (boost::int64_t)stats.nSerializedSize));
        ret.push_back(Pair("hash_serialized", stats.hashSerialized.GetHex()));
        ret.push_back(Pair("total_amount", ValueFromAmount(stats.nTotalAmount)));
    }
    return ret;
}

Value gettxout(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "gettxout <txid> <n> [includemempool=true]\n"
            "Returns details about an unspent transaction output.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    Object ret;

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);
    int n = params[1].get_int();
    bool fMempool = true;
    if (params.size() > 2)
        fMempool = params[2].get_bool();

    CCoins coins;
    if (fMempool) {
        LOCK(mempool.cs);
        CCoinsViewMemPool view(*pcoinsTip, mempool);
        if (!view.GetCoins(hash, coins))
            return Value::null;
        mempool.pruneSpent(hash, coins); // TODO: this should be done by the CCoinsViewMemPool
    } else {
        if (!pcoinsTip->GetCoins(hash, coins))
            return Value::null;
    }
    if (n<0 || (unsigned int)n>=coins.vout.size() || coins.vout[n].IsNull())
        return Value::null;

    ret.push_back(Pair("bestblock", pcoinsTip->GetBestBlock()->GetBlockHash().GetHex()));
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
        ret.push_back(Pair("confirmations", 0));
    else
        ret.push_back(Pair("confirmations", pcoinsTip->GetBestBlock()->nHeight - coins.nHeight + 1));
    ret.push_back(Pair("value", ValueFromAmount(coins.vout[n].nValue)));
    Object o;
    ScriptPubKeyToJSON(coins.vout[n].scriptPubKey, o);
    ret.push_back(Pair("scriptPubKey", o));
    ret.push_back(Pair("version", coins.nVersion));
    ret.push_back(Pair("coinbase", coins.fCoinBase));

    return ret;
}

Value verifychain(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "verifychain [check level] [num blocks]\n"
            "Verifies blockchain database.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    int nCheckLevel = GetArg("-checklevel", 3);
    int nCheckDepth = GetArg("-checkblocks", 288);
    if (params.size() > 0)
        nCheckLevel = params[0].get_int();
    if (params.size() > 1)
        nCheckDepth = params[1].get_int();

    return VerifyDB(nCheckLevel, nCheckDepth);
}

