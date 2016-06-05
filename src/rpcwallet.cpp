// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string.hpp>

#include "wallet.h"
#include "walletdb.h"
#include "bitcoinrpc.h"
#include "init.h"
#include "base58.h"
#include "userdb.h"

#include "mixerann.h"

using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace json_spirit;


std::string HelpRequiringPassphrase(const CRPCContext& ctx)
{
    return ctx.wallet && ctx.wallet->IsCrypted()
        ? "\nrequires wallet passphrase to be set with walletpassphrase first"
        : "";
}

void EnsureWalletIsUnlocked(const CRPCContext& ctx)
{
    if (ctx.wallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
}

void WalletTxToJSON(const CWalletTx& wtx, Object& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(Pair("confirmations", confirms));
    if (wtx.IsCoinBase())
        entry.push_back(Pair("generated", true));
    if (confirms)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
        entry.push_back(Pair("blocktime", (boost::int64_t)(mapBlockIndex[wtx.hashBlock]->nTime)));
    }
    entry.push_back(Pair("txid", wtx.GetHash().GetHex()));
    entry.push_back(Pair("time", (boost::int64_t)wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (boost::int64_t)wtx.nTimeReceived));
    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

string AccountFromValue(const Value& value)
{
    string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}
Value generatekey(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "generatekey"
            "Generates a public/private keypair to use for signing.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    CKey key;
    key.MakeNewKey(false);
    std::stringstream ss;
    CPrivKey priv = key.GetPrivKey();
    CPubKey pub = key.GetPubKey();
    ss << "Public key: " << HexStr(pub) << "\n";
    ss << "Private key: " << HexStr(priv) << "\n";
    return ss.str();
}

Value getinfo(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.");

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    Object obj;
    obj.push_back(Pair("version",       (int)CLIENT_VERSION));
    obj.push_back(Pair("protocolversion",(int)PROTOCOL_VERSION));
    obj.push_back(Pair("blocks",        (int)nBestHeight));
    if (ctx.wallet)
    {
        obj.push_back(Pair("walletversion", ctx.wallet->GetVersion()));
        obj.push_back(Pair("balance",       ValueFromAmount(ctx.wallet->GetBalance())));
        obj.push_back(Pair("keypoololdest", (boost::int64_t)ctx.wallet->GetOldestKeyPoolTime()));
        obj.push_back(Pair("keypoolsize",   (int)ctx.wallet->GetKeyPoolSize()));
        if (ctx.wallet->IsCrypted())
            obj.push_back(Pair("unlocked_until", (boost::int64_t)ctx.wallet->nWalletUnlockTime));
    }
    if (ctx.isAdmin)
    {
        obj.push_back(Pair("timeoffset",    (boost::int64_t)GetTimeOffset()));
        obj.push_back(Pair("connections",   (int)vNodes.size()));
        obj.push_back(Pair("proxy",         (proxy.first.IsValid() ? proxy.first.ToStringIPPort() : string())));
        obj.push_back(Pair("errors",        GetWarnings("statusbar")));
        int usercount = 0;
        if (pusers->ReadLastUserIndex(usercount))
            obj.push_back(Pair("usercount", usercount));
        string rootuser;
        if (pusers->RootAccountGet(rootuser))
            obj.push_back(Pair("rootuser",  rootuser));
    }
    obj.push_back(Pair("difficulty",    (double)GetDifficulty()));
    obj.push_back(Pair("testnet",       fTestNet));
    obj.push_back(Pair("paytxfee",      ValueFromAmount(nTransactionFee)));
    obj.push_back(Pair("mininput",      ValueFromAmount(nMinimumInputValue)));
    obj.push_back(Pair("whoami",        ctx.username));
    return obj;
}



Value getnewaddress(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getnewaddress [account]\n"
            "Returns a new FedoraCoin address for receiving payments.  "
            "If [account] is specified (recommended), it is added to the address book "
            "so payments received with the address will be credited to [account].");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    if (!ctx.wallet->IsLocked())
        ctx.wallet->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!ctx.wallet->GetKeyFromPool(newKey, false))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    ctx.wallet->SetAddressBookName(keyID, strAccount);

    return CBitcoinAddress(keyID).ToString();
}


CBitcoinAddress GetAccountAddress(const CRPCContext& ctx, string strAccount, bool bForceNew=false)
{
    CWalletDB walletdb(ctx.wallet->strWalletFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    bool bKeyUsed = false;

    // Check if the current key has been used
    if (account.vchPubKey.IsValid())
    {
        CScript scriptPubKey;
        scriptPubKey.SetDestination(account.vchPubKey.GetID());
        for (map<uint256, CWalletTx>::iterator it = ctx.wallet->mapWallet.begin();
             it != ctx.wallet->mapWallet.end() && account.vchPubKey.IsValid();
             ++it)
        {
            const CWalletTx& wtx = (*it).second;
            BOOST_FOREACH(const CTxOut& txout, wtx.vout)
                if (txout.scriptPubKey == scriptPubKey)
                    bKeyUsed = true;
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed)
    {
        if (!ctx.wallet->GetKeyFromPool(account.vchPubKey, false))
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

        ctx.wallet->SetAddressBookName(account.vchPubKey.GetID(), strAccount);
        walletdb.WriteAccount(strAccount, account);
    }

    return CBitcoinAddress(account.vchPubKey.GetID());
}

Value getaccountaddress(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccountaddress <account>\n"
            "Returns the current FedoraCoin address for receiving payments to this account.");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]);

    Value ret;

    ret = GetAccountAddress(ctx, strAccount).ToString();

    return ret;
}



Value setaccount(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setaccount <fedoracoinaddress> <account>\n"
            "Sets the account associated with the given address.");

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid FedoraCoin address");


    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Detect when changing the account of an address that is the 'unused current key' of another account:
    if (ctx.wallet->mapAddressBook.count(address.Get()))
    {
        string strOldAccount = ctx.wallet->mapAddressBook[address.Get()];

        if (address == GetAccountAddress(ctx, strOldAccount))
            GetAccountAddress(ctx, strOldAccount, true);
    }

    ctx.wallet->SetAddressBookName(address.Get(), strAccount);

    return Value::null;
}


Value getaccount(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccount <fedoracoinaddress>\n"
            "Returns the account associated with the given address.");

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid FedoraCoin address");

    string strAccount;
    map<CTxDestination, string>::iterator mi = ctx.wallet->mapAddressBook.find(address.Get());
    if (mi != ctx.wallet->mapAddressBook.end() && !(*mi).second.empty())
        strAccount = (*mi).second;
    return strAccount;
}


Value getaddressesbyaccount(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressesbyaccount <account>\n"
            "Returns the list of addresses for the given account.");

    string strAccount = AccountFromValue(params[0]);

    // Find all addresses that have the given account
    Array ret;

    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, ctx.wallet->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
}


Value setmininput(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "setmininput <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.00000001.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    // Amount
    uint64 nAmount = 0;
    if (params[0].get_real() != 0.0)
        nAmount = AmountFromValue(params[0]);        // rejects 0.0 amounts

    nMinimumInputValue = nAmount;
    return true;
}

Value listaddressgroupings(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listaddressgroupings\n"
            "Lists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions.");

    Array jsonGroupings;
    map<CTxDestination, uint64> balances = ctx.wallet->GetAddressBalances();
    BOOST_FOREACH(set<CTxDestination> grouping, ctx.wallet->GetAddressGroupings())
    {
        Array jsonGrouping;
        BOOST_FOREACH(CTxDestination address, grouping)
        {
            Array addressInfo;
            addressInfo.push_back(CBitcoinAddress(address).ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                LOCK(ctx.wallet->cs_wallet);
                if (ctx.wallet->mapAddressBook.find(CBitcoinAddress(address).Get()) != ctx.wallet->mapAddressBook.end())
                    addressInfo.push_back(ctx.wallet->mapAddressBook.find(CBitcoinAddress(address).Get())->second);
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

Value signmessage(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signmessage <fedoracoinaddress> <message>\n"
            "Sign a message with the private key of an address");

    EnsureWalletIsUnlocked(ctx);

    string strAddress = params[0].get_str();
    string strMessage = params[1].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!ctx.wallet->GetKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

Value verifymessage(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "verifymessage <fedoracoinaddress> <signature> <message>\n"
            "Verify a signed message.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strMessage  = params[2].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == keyID);
}


Value getreceivedbyaddress(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaddress <fedoracoinaddress> [minconf=1]\n"
            "Returns the total amount received by <fedoracoinaddress> in transactions with at least [minconf] confirmations.");

    // Bitcoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    CScript scriptPubKey;
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid FedoraCoin address");
    scriptPubKey.SetDestination(address.Get());
    if (!IsMine(*ctx.wallet,scriptPubKey))
        return (double)0.0;

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally
    uint64 nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = ctx.wallet->mapWallet.begin(); it != ctx.wallet->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return  ValueFromAmount(nAmount);
}


void GetAccountAddresses(const CRPCContext& ctx, string strAccount, set<CTxDestination>& setAddress)
{
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, ctx.wallet->mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            setAddress.insert(address);
    }
}

Value getreceivedbyaccount(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaccount <account> [minconf=1]\n"
            "Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.");

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Get the set of pub keys assigned to account
    string strAccount = AccountFromValue(params[0]);
    set<CTxDestination> setAddress;

    GetAccountAddresses(ctx, strAccount, setAddress);

    // Tally
    uint64 nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = ctx.wallet->mapWallet.begin(); it != ctx.wallet->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*ctx.wallet, address) && setAddress.count(address))
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
        }
    }

    return (double)nAmount / (double)COIN;
}

Value getbalance(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getbalance [account] [minconf=1]\n"
            "If [account] is not specified, returns the server's total available balance.\n"
            "If [account] is specified, returns the balance in the account.");

    if (params.size() == 0)
        return  ValueFromAmount(ctx.wallet->GetBalance());

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    if (params[0].get_str() == "*") {
        uint64 nBalance = 0;
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and getbalance '*' 0 should return the same number
        for (map<uint256, CWalletTx>::iterator it = ctx.wallet->mapWallet.begin(); it != ctx.wallet->mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (!wtx.IsConfirmed())
                continue;

            uint64 allFee;
            string strSentAccount;
            list<pair<CTxDestination, uint64> > listReceived;
            list<pair<CTxDestination, uint64> > listSent;
            wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount);
            if (wtx.GetDepthInMainChain() >= nMinDepth)
            {
                BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listReceived)
                    nBalance += r.second;
            }
            BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listSent)
                nBalance -= r.second;
            nBalance -= allFee;
        }
        return  ValueFromAmount(nBalance);
    }

    string strAccount = AccountFromValue(params[0]);

    uint64 nBalance = ctx.wallet->GetAccountBalance(strAccount, nMinDepth);

    return ValueFromAmount(nBalance);
}


Value movecmd(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
            "move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
            "Move from one account in your wallet to another.");

    string strFrom = AccountFromValue(params[0]);
    string strTo = AccountFromValue(params[1]);
    uint64 nAmount = AmountFromValue(params[2]);
    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int();
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str();

    CWalletDB walletdb(ctx.wallet->strWalletFile);
    if (!walletdb.TxnBegin())
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    int64 nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.nOrderPos = ctx.wallet->IncOrderPosNext(&walletdb);
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    walletdb.WriteAccountingEntry(debit);

    // Credit
    CAccountingEntry credit;
    credit.nOrderPos = ctx.wallet->IncOrderPosNext(&walletdb);
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    walletdb.WriteAccountingEntry(credit);

    if (!walletdb.TxnCommit())
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    return true;
}

Value sendtoaddress(const Array& params, const CRPCContext& ctx, bool fHelp)
{    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendtoaddress <fedoracoinaddress>[:mixed] <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001\n"
            "coins can be mixed by appending :mixed to the destination address, which will conceal the address you sent them from."
            + HelpRequiringPassphrase(ctx));

    string strAddress = params[0].get_str();
    size_t iSeperator = strAddress.find_last_of(":");
    bool bMixCoins = false;
    if (iSeperator != std::string::npos)
    {
        string action = strAddress.substr(iSeperator+1);
        strAddress = strAddress.substr(0, iSeperator);
        bMixCoins = boost::iequals(action, "mixed");
    }

    CBitcoinAddress address(strAddress);
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid FedoraCoin address");

    // Amount
    uint64 nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 2 && params[2].type() != null_type && !params[2].get_str().empty())
        wtx.mapValue["comment"] = params[2].get_str();
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["to"]      = params[3].get_str();

    if (ctx.wallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    string strError = ctx.wallet->SendMoneyToDestination(address.Get(), nAmount, wtx, bMixCoins);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

Value sendfrom(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 6)
        throw runtime_error(
            "sendfrom <fromaccount>[:mixed] <tofedoracoinaddress> <amount> [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001\n"
            "coins can be mixed by appending :mixed to the account name, which will conceal the address you sent them from."
            + HelpRequiringPassphrase(ctx));

    string strAccount = AccountFromValue(params[0]);
    size_t iSeperator = strAccount.find_last_of(":");
    bool bMixCoins = false;
    if (iSeperator != std::string::npos)
    {
        string action = strAccount.substr(iSeperator+1);
        strAccount = strAccount.substr(0, iSeperator);
        bMixCoins = boost::iequals(action, "mixed");
    }

    CBitcoinAddress address(params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid FedoraCoin address");
    uint64 nAmount = AmountFromValue(params[2]);
    int nMinDepth = 1;
    if (params.size() > 3)
        nMinDepth = params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str();
    if (params.size() > 5 && params[5].type() != null_type && !params[5].get_str().empty())
        wtx.mapValue["to"]      = params[5].get_str();

    EnsureWalletIsUnlocked(ctx);

    // Check funds
    uint64 nBalance = ctx.wallet->GetAccountBalance(strAccount, nMinDepth);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    string strError = ctx.wallet->SendMoneyToDestination(address.Get(), nAmount, wtx, bMixCoins);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}


Value sendmany(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendmany <fromaccount>[:mixed] {address:amount,...} [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers\n"
            "coins can be mixed by appending :mixed to the account name, which will conceal the address you sent them from."
            + HelpRequiringPassphrase(ctx));

    string strAccount = AccountFromValue(params[0]);
    size_t iSeperator = strAccount.find_last_of(":");
    bool bMixCoins = false;
    if (iSeperator != std::string::npos)
    {
        string action = strAccount.substr(iSeperator+1);
        strAccount = strAccount.substr(0, iSeperator);
        bMixCoins = boost::iequals(action, "mixed");
    }

    Object sendTo = params[1].get_obj();
    int nMinDepth = 1;
    if (params.size() > 2)
        nMinDepth = params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();

    set<CBitcoinAddress> setAddress;
    vector<pair<CScript, uint64> > vecSend;

    uint64 totalAmount = 0;
    BOOST_FOREACH(const Pair& s, sendTo)
    {
        CBitcoinAddress address(s.name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid FedoraCoin address: ")+s.name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+s.name_);
        setAddress.insert(address);

        CScript scriptPubKey;
        scriptPubKey.SetDestination(address.Get());
        uint64 nAmount = AmountFromValue(s.value_);
        totalAmount += nAmount;

        vecSend.push_back(make_pair(scriptPubKey, nAmount));
    }

    EnsureWalletIsUnlocked(ctx);

    // Check funds
    uint64 nBalance = ctx.wallet->GetAccountBalance(strAccount, nMinDepth);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(ctx.wallet);
    uint64 nFeeRequired = 0;
    string strFailReason;
    bool fCreated = ctx.wallet->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, strFailReason, bMixCoins);
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    if (!ctx.wallet->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}

//
// Used by addmultisigaddress / createmultisig:
//
static CScript _createmultisig(const CRPCContext& ctx, const Array& params)
{
    int nRequired = params[0].get_int();
    const Array& keys = params[1].get_array();

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("_createmultisig(): a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("_createmultisig(): not enough keys supplied "
                      "(got %"PRIszu" keys, but need at least %d to redeem)", keys.size(), nRequired));
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();

        // Case 1: FedoraCoin address and we have full public key:
        CBitcoinAddress address(ks);
        if (ctx.wallet && address.IsValid())
        {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw runtime_error(
                    strprintf("_createmultisig(): %s does not refer to a key",ks.c_str()));
            CPubKey vchPubKey;
            if (!ctx.wallet->GetPubKey(keyID, vchPubKey))
                throw runtime_error(
                    strprintf("_createmultisig(): no full public key for address %s",ks.c_str()));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error("_createmultisig(): invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error("_createmultisig(): invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }
        else
        {
            throw runtime_error("_createmultisig(): invalid public key: "+ks);
        }
    }
    CScript result;
    result.SetMultisig(nRequired, pubkeys);
    return result;
}

Value addmultisigaddress(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "addmultisigaddress <nrequired> <'[\"key\",\"key\"]'> [account]\n"
            "Add a nrequired-to-sign multisignature address to the wallet\"\n"
            "each key is a FedoraCoin address or hex-encoded public key\n"
            "If [account] is specified, assign address to [account].");

    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig(ctx, params);
    CScriptID innerID = inner.GetID();
    ctx.wallet->AddCScript(inner);

    ctx.wallet->SetAddressBookName(innerID, strAccount);
    return CBitcoinAddress(innerID).ToString();
}

Value createmultisig(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 2)
        throw runtime_error(
            "createmultisig <nrequired> <'[\"key\",\"key\"]'>\n"
            "Creates a multi-signature address and returns a json object\n"
            "with keys:\n"
            "address : fedoracoin address\n"
            "redeemScript : hex-encoded redemption script.");

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig(ctx, params);
    CScriptID innerID = inner.GetID();
    CBitcoinAddress address(innerID);

    Object result;
    result.push_back(Pair("address", address.ToString()));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));

    return result;
}


struct tallyitem
{
    uint64 nAmount;
    int nConf;
    vector<uint256> txids;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
    }
};

Value ListReceived(const Array& params, const CRPCContext& ctx, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool();

    // Tally
    map<CBitcoinAddress, tallyitem> mapTally;
    for (map<uint256, CWalletTx>::iterator it = ctx.wallet->mapWallet.begin(); it != ctx.wallet->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;

        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address) || !IsMine(*ctx.wallet, address))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
        }
    }

    // Reply
    Array ret;
    map<string, tallyitem> mapAccountTally;
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, ctx.wallet->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strAccount = item.second;

        map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        uint64 nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
        }

        if (fByAccounts)
        {
            tallyitem& item = mapAccountTally[strAccount];
            item.nAmount += nAmount;
            item.nConf = min(item.nConf, nConf);
        }
        else
        {
            Object obj;
            obj.push_back(Pair("address",       address.ToString()));
            obj.push_back(Pair("account",       strAccount));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            Array transactions;
            if (it != mapTally.end())
            {
                BOOST_FOREACH(const uint256& item, (*it).second.txids)
                {
                    transactions.push_back(item.GetHex());
                }
            }
            obj.push_back(Pair("txids", transactions));
            ret.push_back(obj);
        }
    }

    if (fByAccounts)
    {
        for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
        {
            uint64 nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;
            Object obj;
            obj.push_back(Pair("account",       (*it).first));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

Value listreceivedbyaddress(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaddress [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include addresses that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"address\" : receiving address\n"
            "  \"account\" : the account of the receiving address\n"
            "  \"amount\" : total amount received by the address\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included\n"
            "  \"txids\" : list of transactions with outputs to the address.\n");

    return ListReceived(params, ctx, false);
}

Value listreceivedbyaccount(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaccount [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include accounts that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"account\" : the account of the receiving addresses\n"
            "  \"amount\" : total amount received by addresses with this account\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included.");

    return ListReceived(params, ctx, true);
}

void ListTransactions(const CWalletTx& wtx, const string& strAccount, const CRPCContext& ctx, int nMinDepth, bool fLong, Array& ret)
{
    uint64 nFee;
    string strSentAccount;
    list<pair<CTxDestination, uint64> > listReceived;
    list<pair<CTxDestination, uint64> > listSent;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount);

    bool fAllAccounts = (strAccount == string("*"));

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, uint64)& s, listSent)
        {
            Object entry;
            entry.push_back(Pair("account", strSentAccount));
            entry.push_back(Pair("address", CBitcoinAddress(s.first).ToString()));
            entry.push_back(Pair("category", "send"));
            entry.push_back(Pair("amount", ValueFromAmount(-(int64)s.second)));
            entry.push_back(Pair("fee", ValueFromAmount(-(int64)nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, uint64)& r, listReceived)
        {
            string account;
            if (ctx.wallet->mapAddressBook.count(r.first))
                account = ctx.wallet->mapAddressBook[r.first];
            if (fAllAccounts || (account == strAccount))
            {
                Object entry;
                entry.push_back(Pair("account", account));
                entry.push_back(Pair("address", CBitcoinAddress(r.first).ToString()));
                if (wtx.IsCoinBase())
                {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.push_back(Pair("category", "orphan"));
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.push_back(Pair("category", "immature"));
                    else
                        entry.push_back(Pair("category", "generate"));
                }
                else
                    entry.push_back(Pair("category", "receive"));
                entry.push_back(Pair("amount", ValueFromAmount(r.second)));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }
}

void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Array& ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        Object entry;
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", (boost::int64_t)acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

Value listtransactions(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listtransactions [account] [count=10] [from=0]\n"
            "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");

    string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    Array ret;

    std::list<CAccountingEntry> acentries;
    CWallet::TxItems txOrdered = ctx.wallet->OrderedTxItems(acentries, strAccount);

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, ctx, 0, true, ret);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount+nFrom)) break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;
    Array::iterator first = ret.begin();
    std::advance(first, nFrom);
    Array::iterator last = ret.begin();
    std::advance(last, nFrom+nCount);

    if (last != ret.end()) ret.erase(last, ret.end());
    if (first != ret.begin()) ret.erase(ret.begin(), first);

    std::reverse(ret.begin(), ret.end()); // Return oldest to newest

    return ret;
}

Value listaccounts(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "listaccounts [minconf=1]\n"
            "Returns Object that has account names as keys, account balances as values.");

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    map<string, uint64> mapAccountBalances;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, ctx.wallet->mapAddressBook) {
        if (IsMine(*ctx.wallet, entry.first)) // This address belongs to me
            mapAccountBalances[entry.second] = 0;
    }

    for (map<uint256, CWalletTx>::iterator it = ctx.wallet->mapWallet.begin(); it != ctx.wallet->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        uint64 nFee;
        string strSentAccount;
        list<pair<CTxDestination, uint64> > listReceived;
        list<pair<CTxDestination, uint64> > listSent;
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount);

        mapAccountBalances[strSentAccount] -= nFee;
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, uint64)& s, listSent)
            mapAccountBalances[strSentAccount] -= s.second;

        if (wtx.GetDepthInMainChain() >= nMinDepth)
        {
            BOOST_FOREACH(const PAIRTYPE(CTxDestination, uint64)& r, listReceived)
            {
                if (ctx.wallet->mapAddressBook.count(r.first))
                {
                    string acct = ctx.wallet->mapAddressBook[r.first];
                    mapAccountBalances[acct] += r.second;
                }
                else
                    mapAccountBalances[""] += r.second;
            }
        }
    }

    list<CAccountingEntry> acentries;
    CWalletDB(ctx.wallet->strWalletFile).ListAccountCreditDebit("*", acentries);
    BOOST_FOREACH(const CAccountingEntry& entry, acentries)
            mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    Object ret;
    BOOST_FOREACH(const PAIRTYPE(string, uint64)& accountBalance, mapAccountBalances) {
        ret.push_back(Pair(accountBalance.first, ValueFromAmount((int64)accountBalance.second)));
    }
    return ret;
}

Value listsinceblock(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listsinceblock [blockhash] [target-confirmations]\n"
            "Get all transactions in blocks since block [blockhash], or all transactions if omitted.");

    CBlockIndex *pindex = NULL;
    int target_confirms = 1;

    if (params.size() > 0)
    {
        uint256 blockId = 0;

        blockId.SetHex(params[0].get_str());
        pindex = CBlockLocator(blockId).GetBlockIndex();
    }

    if (params.size() > 1)
    {
        target_confirms = params[1].get_int();

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    int depth = pindex ? (1 + nBestHeight - pindex->nHeight) : -1;

    Array transactions;

    for (map<uint256, CWalletTx>::iterator it = ctx.wallet->mapWallet.begin(); it != ctx.wallet->mapWallet.end(); it++)
    {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth)
            ListTransactions(tx, "*", ctx, 0, true, transactions);
    }

    uint256 lastblock;

    if (target_confirms == 1)
    {
        lastblock = hashBestChain;
    }
    else
    {
        int target_height = pindexBest->nHeight + 1 - target_confirms;

        CBlockIndex *block;
        for (block = pindexBest;
             block && block->nHeight > target_height;
             block = block->pprev)  { }

        lastblock = block ? block->GetBlockHash() : 0;
    }

    Object ret;
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}

Value gettransaction(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "gettransaction <txid>\n"
            "Get detailed information about in-wallet transaction <txid>.");

    uint256 hash;
    hash.SetHex(params[0].get_str());

    Object entry;
    if (!ctx.wallet->mapWallet.count(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    const CWalletTx& wtx = ctx.wallet->mapWallet[hash];

    uint64 nCredit = wtx.GetCredit();
    uint64 nDebit = wtx.GetDebit();
    int64 nNet = nCredit - nDebit;
    uint64 nFeeAmount = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);

    entry.push_back(Pair("amount", ValueFromAmount(nNet - (int64)nFeeAmount)));
    if (wtx.IsFromMe())
        entry.push_back(Pair("fee", ValueFromAmount(nFeeAmount)));

    WalletTxToJSON(wtx, entry);

    Array details;
    ListTransactions(wtx, "*", ctx, 0, false, details);
    entry.push_back(Pair("details", details));

    return entry;
}


Value backupwallet(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "backupwallet <destination>\n"
            "Safely copies wallet.dat to destination, which can be a directory or a path with filename.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    string strDest = params[0].get_str();
    if (!BackupWallet(*ctx.wallet, strDest))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");

    return Value::null;
}


Value keypoolrefill(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "keypoolrefill\n"
            "Fills the keypool."
            + HelpRequiringPassphrase(ctx));

    EnsureWalletIsUnlocked(ctx);

    ctx.wallet->TopUpKeyPool();

    if (ctx.wallet->GetKeyPoolSize() < GetArg("-keypool", 100))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return Value::null;
}


void ThreadTopUpKeyPool(void* parg)
{
    // Make this thread recognisable as the key-topping-up thread
    RenameThread("bitcoin-key-top");

    ((CWallet*)parg)->TopUpKeyPool();
}

void ThreadCleanWalletPassphrase(const void* parg1, void* parg2)
{
    // Make this thread recognisable as the wallet relocking thread
    RenameThread("bitcoin-lock-wa");

    int64 nMyWakeTime = GetTimeMillis() + *((int64*)parg2) * 1000;

    const CRPCContext* ctx = (const CRPCContext*)parg1;

    ENTER_CRITICAL_SECTION(ctx->wallet->cs_nWalletUnlockTime);

    if (ctx->wallet->nWalletUnlockTime == 0)
    {
        ctx->wallet->nWalletUnlockTime = nMyWakeTime;

        do
        {
            if (ctx->wallet->nWalletUnlockTime==0)
                break;
            int64 nToSleep = ctx->wallet->nWalletUnlockTime - GetTimeMillis();
            if (nToSleep <= 0)
                break;

            LEAVE_CRITICAL_SECTION(ctx->wallet->cs_nWalletUnlockTime);
            MilliSleep(nToSleep);
            ENTER_CRITICAL_SECTION(ctx->wallet->cs_nWalletUnlockTime);

        } while(1);

        if (ctx->wallet->nWalletUnlockTime)
        {
            ctx->wallet->nWalletUnlockTime = 0;
            ctx->wallet->Lock();
        }
    }
    else
    {
        if (ctx->wallet->nWalletUnlockTime < nMyWakeTime)
            ctx->wallet->nWalletUnlockTime = nMyWakeTime;
    }

    LEAVE_CRITICAL_SECTION(ctx->wallet->cs_nWalletUnlockTime);


    delete (int64*)parg2;
}

Value walletpassphrase(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (ctx.wallet->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    if (fHelp)
        return true;

    if (!ctx.wallet->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");

    if (!ctx.wallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_ALREADY_UNLOCKED, "Error: Wallet is already unlocked.");

    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!ctx.wallet->Unlock(strWalletPass))
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    NewThread(ThreadTopUpKeyPool, ctx.wallet);
    int64* pnSleepTime = new int64(params[1].get_int64());
    NewThread2(ThreadCleanWalletPassphrase, &ctx, pnSleepTime);

    return Value::null;
}


Value walletpassphrasechange(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (ctx.wallet->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
    if (fHelp)
        return true;

    if (!ctx.wallet->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!ctx.wallet->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    return Value::null;
}


Value walletlock(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (ctx.wallet->IsCrypted() && (fHelp || params.size() != 0))
        throw runtime_error(
            "walletlock\n"
            "Removes the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.");
    if (fHelp)
        return true;

    if (!ctx.wallet->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");
    {
        LOCK(ctx.wallet->cs_nWalletUnlockTime);
        ctx.wallet->Lock();
        ctx.wallet->nWalletUnlockTime = 0;
    }

    return Value::null;
}


Value encryptwallet(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (!ctx.wallet->IsCrypted() && (fHelp || params.size() != 1))
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    if (fHelp)
        return true;

    if (ctx.wallet->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!ctx.wallet->EncryptWallet(strWalletPass))
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();
    return "wallet encrypted; FedoraCoin server stopping, restart to run with encrypted wallet. The keypool has been flushed, you need to make a new backup.";
}

CCriticalSection cs_describeWallet;
CWallet* describeWallet;

class DescribeAddressVisitor : public boost::static_visitor<Object>
{
public:
    Object operator()(const CNoDestination &dest) const { return Object(); }

    Object operator()(const CKeyID &keyID) const {
        Object obj;
        CPubKey vchPubKey;
        describeWallet->GetPubKey(keyID, vchPubKey);
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("pubkey", HexStr(vchPubKey)));
        obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        return obj;
    }

    Object operator()(const CScriptID &scriptID) const {
        Object obj;
        obj.push_back(Pair("isscript", true));
        CScript subscript;
        describeWallet->GetCScript(scriptID, subscript);
        std::vector<CTxDestination> addresses;
        txnouttype whichType;
        int nRequired;
        ExtractDestinations(subscript, whichType, addresses, nRequired);
        obj.push_back(Pair("script", GetTxnOutputType(whichType)));
        Array a;
        BOOST_FOREACH(const CTxDestination& addr, addresses)
            a.push_back(CBitcoinAddress(addr).ToString());
        obj.push_back(Pair("addresses", a));
        if (whichType == TX_MULTISIG)
            obj.push_back(Pair("sigsrequired", nRequired));
        return obj;
    }
};

Value validateaddress(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress <fedoracoinaddress>\n"
            "Return information about <fedoracoinaddress>.");

    CBitcoinAddress address(params[0].get_str());
    bool isValid = address.IsValid();

    Object ret;
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));
        bool fMine = ctx.wallet ? IsMine(*ctx.wallet, dest) : false;
        ret.push_back(Pair("ismine", fMine));
        if (fMine) {
            LOCK(cs_describeWallet);
            describeWallet = ctx.wallet;
            Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
            ret.insert(ret.end(), detail.begin(), detail.end());
        }
        if (ctx.wallet && ctx.wallet->mapAddressBook.count(dest))
            ret.push_back(Pair("account", ctx.wallet->mapAddressBook[dest]));
    }
    return ret;
}

Value lockunspent(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "lockunspent unlock? [array-of-Objects]\n"
            "Updates list of temporarily unspendable outputs.");

    if (params.size() == 1)
        RPCTypeCheck(params, list_of(bool_type));
    else
        RPCTypeCheck(params, list_of(bool_type)(array_type));

    bool fUnlock = params[0].get_bool();

    if (params.size() == 1) {
        if (fUnlock)
            ctx.wallet->UnlockAllCoins();
        return true;
    }

    Array outputs = params[1].get_array();
    BOOST_FOREACH(Value& output, outputs)
    {
        if (output.type() != obj_type)
            throw JSONRPCError(-8, "Invalid parameter, expected object");
        const Object& o = output.get_obj();

        RPCTypeCheck(o, map_list_of("txid", str_type)("vout", int_type));

        string txid = find_value(o, "txid").get_str();
        if (!IsHex(txid))
            throw JSONRPCError(-8, "Invalid parameter, expected hex txid");

        int nOutput = find_value(o, "vout").get_int();
        if (nOutput < 0)
            throw JSONRPCError(-8, "Invalid parameter, vout must be positive");

        COutPoint outpt(uint256(txid), nOutput);

        if (fUnlock)
            ctx.wallet->UnlockCoin(outpt);
        else
            ctx.wallet->LockCoin(outpt);
    }

    return true;
}

Value listlockunspent(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "listlockunspent\n"
            "Returns list of temporarily unspendable outputs.");

    vector<COutPoint> vOutpts;
    ctx.wallet->ListLockedCoins(vOutpts);

    Array ret;

    BOOST_FOREACH(COutPoint &outpt, vOutpts) {
        Object o;

        o.push_back(Pair("txid", outpt.hash.GetHex()));
        o.push_back(Pair("vout", (int)outpt.n));
        ret.push_back(o);
    }

    return ret;
}

