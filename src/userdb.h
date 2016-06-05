// Copyright (c) 2013-2014 The FedoraCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_USERDB_LEVELDB_H
#define BITCOIN_USERDB_LEVELDB_H

#include "main.h"
#include "leveldb.h"

/** Access to the user database (users/) */
class CUserDB : public CLevelDB
{
public:
    CUserDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
private:
    CUserDB(const CUserDB&);
    void operator=(const CUserDB&);
public:
    std::string root;
    bool WriteLastUserIndex(int nLastIdx);
    bool ReadLastUserIndex(int &nLastIdx);
    bool RootAccountExists();
    bool RootAccountSet(std::string username);
    bool RootAccountGet(std::string &username);
    bool UserExists(std::string username);
    bool UserAdd(std::string username, const SecureString &password);
    bool UserUpdate(std::string username, const SecureString &password);
    bool UserAuth(std::string username, const SecureString &password);
};

#endif // BITCOIN_TXDB_LEVELDB_H
