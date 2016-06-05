// Copyright (c) 2013-2014 The FedoraCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _MIXERANN_H_
#define _MIXERANN_H_ 1

#include <set>
#include <string>

#include "uint256.h"
#include "util.h"
#include "sync.h"

class CNode;

/** Alerts are for notifying old versions if they become too obsolete and
 * need to upgrade.  The message is displayed in the status bar.
 * Alert messages are broadcast as a vector of signed data.  Unserializing may
 * not read the entire buffer if the alert is for a newer version, but older
 * versions can still relay the original data.
 */
class CUnsignedAnnouncement
{
public:
    int nVersion;
    int64 nExpiration;      // when the alert is no longer in effect
    int nID;                  // unique id for the alert
    std::set<int> setRevoke;  // empty = no revokement

    int nMinVer;            // lowest version inclusive
    int nMaxVer;            // highest version inclusive
    std::set<std::string> setSubVer;  // empty matches all

    std::vector<unsigned char> pReceiveAddressPubKey;
    std::vector<unsigned char> pSendAddressPubKey;
    std::vector<unsigned char> pRsaPubKey;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nExpiration);
        READWRITE(nID);
        READWRITE(setRevoke);

        READWRITE(nMinVer);
        READWRITE(nMaxVer);
        READWRITE(setSubVer);

        READWRITE(pReceiveAddressPubKey);
        READWRITE(pSendAddressPubKey);
        READWRITE(pRsaPubKey);
    )

    void SetNull();

    std::string ToString() const;
    void print() const;
};

/** An announcement is a combination of a serialized CUnsignedAnnouncement and a signature. */
class CAnnouncement : public CUnsignedAnnouncement
{
public:
    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CAnnouncement()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchMsg);
        READWRITE(vchSig);
    )

    void SetNull();
    bool IsNull() const;
    uint256 GetHash() const;
    bool IsInEffect() const;
    bool Cancels(const CAnnouncement& ann) const;
    bool AppliesTo(int nVersion, std::string strSubVerIn) const;
    bool AppliesToMe() const;
    bool RelayTo(CNode* pnode) const;
    bool CheckSignature() const;
    bool ProcessAnnouncement(bool fThread = true);
    bool IsAnnouncement() const;

    /*
     * Get copy of (active) announcement object by hash. Returns a null alert if it is not found.
     */
    static CAnnouncement getAnnouncementByHash(const uint256 &hash);
};

#endif
