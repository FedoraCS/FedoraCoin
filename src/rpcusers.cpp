// Copyright (c) 2013-2014 The FedoraCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "base58.h"
#include "userdb.h"
#include <boost/lexical_cast.hpp>

#define printf OutputDebugStringF

using namespace json_spirit;
using namespace std;

Value adduser(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || (ctx.isAdmin && params.size() != 2))
        throw runtime_error(
            "adduser <username> <password>\n"
            "Allows the login combination to access the server via RPC.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    string strUser = params[0].get_str();
    SecureString pass;
    pass.reserve(MAX_PASSPHRASE_SIZE);
    pass = params[1].get_str().c_str();
    if (!pusers->UserAdd(strUser, pass))
        throw JSONRPCError(RPC_INVALID_PARAMS, "Add user failed");
    return true;
}
Value passwd(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || (ctx.isAdmin && params.size() != 2) || (!ctx.isAdmin && params.size() != 1))
    {
        string start = (ctx.isAdmin ? "passwd <username> <password>\n" : "passwd <password>\n");
        throw runtime_error(
            start +
            "Updates user password.");
    }

    if (params.size() == 2 && !ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    string strUser = params[0].get_str();
    SecureString strNewPass;
    strNewPass.reserve(MAX_PASSPHRASE_SIZE);
    if (params.size() > 1)
        strNewPass = params[1].get_str().c_str();
    else
    {
        strNewPass = strUser.c_str();
        strUser = ctx.username;
    }
    if (!pusers->UserExists(strUser))
        throw JSONRPCError(RPC_INVALID_PARAMS, "User not found");
    if (!pusers->UserUpdate(strUser, strNewPass))
        throw JSONRPCError(RPC_INVALID_PARAMS, "User update failed");

    return true;
}
Value authuser(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "authuser <username> <password>\n"
            "Tests the username and password to see if the user can login.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    string strUser = params[0].get_str();
    SecureString strPass;
    strPass.reserve(MAX_PASSPHRASE_SIZE);
    strPass = params[1].get_str().c_str();

    return pusers->UserAuth(strUser, strPass);
}
Value whoami(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "whoami\n"
            "Prints the currently logged in users name.");

    return ctx.username;
}

Value root(const Array& params, const CRPCContext& ctx, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "root"
            "Prints the root username.");

    if (!ctx.isAdmin) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (unauthorized)");

    string user;
    pusers->RootAccountGet(user);
    return user;
}
