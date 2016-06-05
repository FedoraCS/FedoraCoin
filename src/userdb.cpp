// Copyright (c) 2013-2014 The FedoraCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "userdb.h"
#include "hash.h"
#include "wallet.h"
#include "bitcoinrpc.h"
#include <boost/lexical_cast.hpp>
using namespace std;
CCriticalSection cs_userCount;

CUserDB::CUserDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDB(GetDataDir() / "users", nCacheSize, fMemory, fWipe) {
}
bool CUserDB::WriteLastUserIndex(int bLastIdx)
{
    LOCK(cs_userCount);
    return Write('U', bLastIdx);
}

bool CUserDB::ReadLastUserIndex(int& bLastIdx)
{
    LOCK(cs_userCount);
    int defaultidx = 0;
    if (!Read('U', bLastIdx))
        Write('U', defaultidx);
    return Read('U', bLastIdx);
}

bool CUserDB::UserExists(string username)
{
    if (username == "root" || username == "false") return true;
    uint256 pass_hash("0x0");
    return Read("U:" + username, pass_hash) && pass_hash != uint256("0x0");
}

bool CUserDB::RootAccountExists()
{
    std::string owner;
    if (Read(string("ROOT"), owner) && !owner.empty())
    {
        this->root = owner;
        return true;
    }
    return false;
}

bool CUserDB::RootAccountSet(string username)
{
    string user = username;
    std::transform(user.begin(), user.end(), user.begin(), ::tolower);
    bool w = Write(string("ROOT"), user);
    if (w) this->root = user;
    return w;
}

bool CUserDB::RootAccountGet(string &username)
{
    string rot;
    bool r = Read(string("ROOT"), rot);
    if (r) username = rot;
    return r;
}

bool CUserDB::UserAdd(string username, const SecureString& password)
{
    string user = username;
    std::transform(user.begin(), user.end(), user.begin(), ::tolower);
    if (this->UserExists(user)) return false;

    // generate a salt for the user
    unsigned char rand_pwd[32];
    RAND_bytes(rand_pwd, 32);
    std::string salt = EncodeBase58(&rand_pwd[0],&rand_pwd[0]+32).c_str();

    // create a password hash like hash(DataStream(hash(password) + hash(salt)))
    CDataStream ds(SER_NETWORK, 0);
    ds << Hash(password.begin(), password.end());//password;
    ds << Hash(salt.begin(), salt.end());
    uint256 pass_hash = Hash(ds.begin(), ds.end());

    // encrypt wallet if it's not encrypted and not the main wallet
    CRPCContext ctx;
    ctx.username = username;
    CWallet* userWallet = CWallet::GetUserWallet(ctx, NULL);
    if (userWallet && !userWallet->IsCrypted() && userWallet != pwalletMain)
        userWallet->EncryptWallet(password);

    // set the user and user salt in the database
    // also set our root user if it hasn't been set before
    if (userWallet && Write("U:" + user, pass_hash) && Write("US:" + user, salt) && (!this->RootAccountExists() ? this->RootAccountSet(user) : true))
    {
        int last = 0;
        this->ReadLastUserIndex(last);
        this->WriteLastUserIndex(last+1);
        return true;
    }
    return false;
}

bool CUserDB::UserUpdate(string username, const SecureString& password)
{
    string user = username;
    std::transform(user.begin(), user.end(), user.begin(), ::tolower);
    if (user == "root" || user == "false") return false;
    if (!this->UserExists(user)) return false;
    string salt;
    if (!Read("US:" + user, salt)) return false;

    CDataStream ds(SER_NETWORK, 0);
    ds << Hash(password.begin(), password.end());
    ds << Hash(salt.begin(), salt.end());
    uint256 pass_hash = Hash(ds.begin(), ds.end());

    return Write("U:" + user, pass_hash);
}

bool CUserDB::UserAuth(string username, const SecureString& password)
{
    string user = username;
    std::transform(user.begin(), user.end(), user.begin(), ::tolower);

    if (user == "root" || user == "false") return false;
    uint256 pass_hash("0x0");
    string salt;
    if (!Read("U:" + user, pass_hash) || !Read("US:" + user, salt) || pass_hash == uint256("0x0")) return false;
    CDataStream ds(SER_NETWORK, 0);
    ds << Hash(password.begin(), password.end());
    ds << Hash(salt.begin(), salt.end());
    uint256 auth_hash = Hash(ds.begin(), ds.end());
    return pass_hash == auth_hash;
}

